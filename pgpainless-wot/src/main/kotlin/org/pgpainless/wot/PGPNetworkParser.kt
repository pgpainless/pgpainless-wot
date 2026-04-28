// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import java.io.IOException
import java.util.*
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKeyReader
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.bouncycastle.PolicyAdapter
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.wot.PGPNetworkParser.Companion.RevocationState
import org.pgpainless.wot.network.Identifier
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.network.RevocationState
import org.pgpainless.wot.util.CertificationFactory.Companion.fromCertification
import org.pgpainless.wot.util.CertificationFactory.Companion.fromDelegation
import org.slf4j.LoggerFactory
import pgp.cert_d.PGPCertificateDirectory
import pgp.cert_d.PGPCertificateStoreAdapter
import pgp.cert_d.SpecialNames
import pgp.certificate_store.PGPCertificateStore
import pgp.certificate_store.certificate.Certificate

/**
 * Create a Network based on a [PGPCertificateStore] instance.
 *
 * @param certificateStore certificate store
 */
class PGPNetworkParser(private val certificateStore: PGPCertificateStore) {

    private val api = PGPainless.getInstance()

    /**
     * Create a Network based on a [PGPCertificateDirectory] instance, which gets adapted to the
     * [PGPCertificateStore] interface.
     *
     * @param certificateDirectory PGP-Certificate-Directory instance
     */
    constructor(
        certificateDirectory: PGPCertificateDirectory
    ) : this(PGPCertificateStoreAdapter(certificateDirectory))

    /**  */
    fun buildNetwork(policy: Policy = api.algorithmPolicy, referenceTime: Date = Date()): Network {
        val certificates = getAllCertificatesFromTheStore()
        val networkFactory = PGPNetworkFactory.fromCertificates(certificates, policy, referenceTime)
        return networkFactory.buildNetwork()
    }

    /**
     * Return a [Sequence] containing all [Certificates][Certificate] in the [PGPCertificateStore],
     * with the specially named "trust-root" certificate optionally appended if present.
     */
    private fun getAllCertificatesFromTheStore(): Sequence<Certificate> {
        var trustRoot: Certificate? = null
        try {
            trustRoot = certificateStore.getCertificate(SpecialNames.TRUST_ROOT)
        } catch (e: NoSuchElementException) {
            // ignore
        }

        val certificates =
            if (trustRoot == null) {
                certificateStore.certificates.asSequence()
            } else {
                sequenceOf(trustRoot) + certificateStore.certificates.asSequence()
            }
        return certificates
    }

    /**
     * Class for building the [Flow network][Network] from the given set of OpenPGP keys.
     *
     * @param validatedCertificates list of validated certificates
     * @param policy policy for signature evaluation
     * @param referenceTime reference time for network evaluation
     */
    private class PGPNetworkFactory
    private constructor(
        validatedCertificates: List<OpenPGPCertificate>,
        private val policy: Policy,
        private val referenceTime: Date
    ) {
        private val networkBuilder: Network.Builder = Network.builder()

        // certificates keyed by fingerprint
        private val byFingerprint: MutableMap<Identifier, OpenPGPCertificate> = HashMap()

        // certificates keyed by (sub-) key-id
        private val byKeyId: MutableMap<KeyIdentifier, MutableList<OpenPGPCertificate>> = HashMap()

        // nodes keyed by fingerprint
        private val nodeMap: MutableMap<Identifier, Node> = HashMap()

        init {
            validatedCertificates.forEach { indexAsNode(it) }
            validatedCertificates.forEach { indexIncomingEdges(it) }
        }

        /**
         * Index the certificate by its [Identifier] and subkey-IDs and add it as a node to the
         * [Network.Builder].
         *
         * @param cert validated certificate
         */
        private fun indexAsNode(cert: OpenPGPCertificate) {
            val info = PGPainless.getInstance().inspect(cert)
            // certificate expiration date
            val expirationDate: Date? =
                try {
                    info.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER)
                } catch (e: NoSuchElementException) {
                    LOGGER.warn(
                        "Could not deduce expiration time of ${cert.fingerprint}. " +
                            "Possibly hard revoked cert or illegal algorithms? Skip certificate.")
                    // Some keys are malformed and have no KeyFlags
                    // TODO: We also end up here for expired keys unfortunately
                    return
                }

            // index by fingerprint
            val certFingerprint = Fingerprint(OpenPgpFingerprint.of(cert))
            byFingerprint.putIfAbsent(certFingerprint, cert)

            // index by key-ID
            cert.allKeyIdentifiers.forEach { byKeyId.getOrPut(it) { mutableListOf() }.add(cert) }

            // map user-ids to revocation states
            val userIds =
                cert.allUserIds
                    // .filter { it.isBoundAt(referenceTime) }
                    .map { it.userId }
                    .associateWith {
                        RevocationState(cert.getUserId(it).getRevocation(referenceTime)?.signature)
                    }

            val node =
                Node(
                    certFingerprint,
                    expirationDate,
                    RevocationState(
                        cert.primaryKey
                            .getRevocation(referenceTime)
                            // We need to filter out non-KEY_REVOCATION signatures
                            ?.let {
                                if (it.signature.signatureType == PGPSignature.KEY_REVOCATION) it
                                else null
                            }
                            ?.signature),
                    userIds)

            nodeMap[certFingerprint] = node
            networkBuilder.addNode(node)
        }

        /**
         * Add all verifiable certifications on the certificate as incoming edges to the
         * [Network.Builder].
         *
         * @param validatedTarget validated certificate
         */
        private fun indexIncomingEdges(validatedTarget: OpenPGPCertificate) {
            // Direct-Key Signatures (delegations) by X on Y
            val delegators =
                validatedTarget.allThirdPartyKeySignatures
                    .map { it.keyIdentifier }
                    .flatMap { byKeyId[it]?.toList() ?: emptyList() }
                    .toSet()
            for (delegator in delegators) {
                validatedTarget
                    .getDelegationsBy(delegator)
                    .getChainsAt(referenceTime)
                    .plus(validatedTarget.getRevocationsBy(delegator).getChainsAt(referenceTime))
                    .forEach {
                        if (it.isValid &&
                            it.signature.issuer.isBoundAt(it.signature.creationTime)) {
                            networkBuilder.addEdge(
                                fromDelegation(
                                    getNode(delegator)!!,
                                    getNode(validatedTarget)!!,
                                    it.signature.signature))
                        }
                    }
            }

            // EdgeComponent Signatures by X on Y over user-ID U
            val userIds = validatedTarget.allUserIds
            for (userId in userIds) {
                // There are potentially multiple certifications per user-ID
                processUserId(userId)
            }
        }

        private fun processUserId(userId: OpenPGPCertificate.OpenPGPUserId) {
            val certifiers =
                userId.thirdPartyCertifications
                    .plus(userId.thirdPartyRevocations)
                    .map { it.keyIdentifier }
                    .flatMap { byKeyId[it]?.toList() ?: emptyList() }
                    .toSet()
            for (issuer in certifiers) {
                userId
                    .getCertificationsBy(issuer)
                    .getChainsAt(referenceTime)
                    .plus(userId.getRevocationsBy(issuer).getChainsAt(referenceTime))
                    .forEach {
                        if (it.isValid &&
                            it.signature.issuer.isBoundAt(it.signature.creationTime)) {
                            networkBuilder.addEdge(
                                fromCertification(
                                    getNode(issuer)!!,
                                    getNode(userId.certificate)!!,
                                    userId.userId,
                                    it.signature.signature))
                        }
                    }
            }
        }

        private fun getNode(cert: OpenPGPCertificate): Node? {
            return nodeMap[Fingerprint(OpenPgpFingerprint.of(cert))]
        }

        /**
         * Map an [OpenPgpFingerprint] to a [Identifier].
         *
         * @param fingerprint [OpenPgpFingerprint]
         */
        private fun Fingerprint(fingerprint: OpenPgpFingerprint) =
            Identifier(fingerprint.toString())

        /**
         * Return the constructed, initialized [Network].
         *
         * @return finished network
         */
        fun buildNetwork(): Network {
            return networkBuilder.build()
        }

        // static factory methods
        companion object {
            @JvmStatic private val LOGGER = LoggerFactory.getLogger(PGPNetworkFactory::class.java)

            /**
             * Create a [PGPNetworkFactory] from a [Sequence] of [Certificates][Certificate]. This
             * method validates the certificates and then creates a [PGPNetworkFactory] from them.
             *
             * @param certificates certificates, e.g. acquired from a [PGPCertificateStore]
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for network evaluation
             */
            @JvmStatic
            fun fromCertificates(
                certificates: Sequence<Certificate>,
                policy: Policy,
                referenceTime: Date
            ): PGPNetworkFactory {
                return fromValidCertificates(
                    parseValidCertificates(certificates, policy), policy, referenceTime)
            }

            /**
             * Create a [PGPNetworkFactory] from a list of [validated certificates][KeyRingInfo].
             *
             * @param certificates already validated certificates
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for network evaluation
             */
            @JvmStatic
            fun fromValidCertificates(
                certificates: List<OpenPGPCertificate>,
                policy: Policy,
                referenceTime: Date
            ): PGPNetworkFactory {
                return PGPNetworkFactory(certificates, policy, referenceTime)
            }

            /**
             * Evaluate the given [Sequence] of [Certificates][Certificate] and transform it into a
             * [List] of [validated certificates][KeyRingInfo].
             *
             * @param certificates certificates
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for signature evaluation
             */
            @JvmStatic
            private fun parseValidCertificates(
                certificates: Sequence<Certificate>,
                policy: Policy
            ): List<OpenPGPCertificate> {
                val reader =
                    OpenPGPKeyReader(PGPainless.getInstance().implementation, PolicyAdapter(policy))
                return certificates
                    .mapNotNull {
                        try {
                            reader.parseKeyOrCertificate(it.inputStream)
                        } catch (e: IOException) {
                            null
                        }
                    }
                    .toList()
            }
        }
    }

    companion object {

        @JvmStatic
        /**
         * Map a [PGPSignature] to its [RevocationState].
         *
         * @param revocation optional revocation signature
         */
        fun RevocationState(revocation: PGPSignature?): RevocationState {
            if (revocation == null) {
                return RevocationState.notRevoked()
            }
            val revocationReason =
                SignatureSubpacketsUtil.getRevocationReason(revocation)
                    ?: return RevocationState.hardRevoked()
            return if (RevocationAttributes.Reason.isHardRevocation(
                revocationReason.revocationReason))
                RevocationState.hardRevoked()
            else RevocationState.softRevoked(revocation.creationTime)
        }
    }
}
