// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.policy.Policy
import org.pgpainless.signature.SignatureUtils
import org.pgpainless.signature.consumer.SignatureValidator
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
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
import java.io.IOException
import java.util.*

/**
 * Create a Network based on a [PGPCertificateStore] instance.
 *
 * @param certificateStore certificate store
 */
class PGPNetworkParser(private val certificateStore: PGPCertificateStore) {

    /**
     * Create a Network based on a [PGPCertificateDirectory] instance, which gets adapted to the
     * [PGPCertificateStore] interface.
     *
     * @param certificateDirectory PGP-Certificate-Directory instance
     */
    constructor(certificateDirectory: PGPCertificateDirectory):
            this(PGPCertificateStoreAdapter(certificateDirectory))

    /**
     *
     */
    fun buildNetwork(policy: Policy = PGPainless.getPolicy(),
                     referenceTime: Date = Date()): Network {
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

        val certificates = if (trustRoot == null) {
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
    private class PGPNetworkFactory private constructor(validatedCertificates: List<KeyRingInfo>,
                                                        private val policy: Policy,
                                                        private val referenceTime: Date) {
        private val networkBuilder: Network.Builder = Network.builder()

        // certificates keyed by fingerprint
        private val byFingerprint: MutableMap<Identifier, KeyRingInfo> = HashMap()

        // certificates keyed by (sub-) key-id
        private val byKeyId: MutableMap<Long, MutableList<KeyRingInfo>> = HashMap()

        // nodes keyed by fingerprint
        private val nodeMap: MutableMap<Identifier, Node> = HashMap()

        init {
            validatedCertificates.forEach { indexAsNode(it) }
            validatedCertificates.forEach { indexIncomingEdges(it) }
        }

        /**
         * Index the certificate by its [Identifier] and subkey-IDs and add it as a node to
         * the [Network.Builder].
         *
         * @param cert validated certificate
         */
        private fun indexAsNode(cert: KeyRingInfo) {

            // certificate expiration date
            val expirationDate: Date? = try {
                cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER)
            } catch (e: NoSuchElementException) {
                LOGGER.warn("Could not deduce expiration time of ${cert.fingerprint}. " +
                        "Possibly hard revoked cert or illegal algorithms? Skip certificate.");
                // Some keys are malformed and have no KeyFlags
                // TODO: We also end up here for expired keys unfortunately
                return
            }

            // index by fingerprint
            val certFingerprint = Fingerprint(cert.fingerprint)
            byFingerprint.putIfAbsent(certFingerprint, cert)

            // index by key-ID
            cert.keys.publicKeys.forEach {
                byKeyId.getOrPut(it.keyID) { mutableListOf() }.add(cert)
            }

            // map user-ids to revocation states
            val userIds = cert.userIds.associateWith { RevocationState(cert.getUserIdRevocation(it)) }

            val node = Node(certFingerprint,
                    expirationDate,
                    RevocationState(cert.revocationSelfSignature),
                    userIds)

            nodeMap[certFingerprint] = node
            networkBuilder.addNode(node)
        }

        /**
         * Add all verifiable certifications on the certificate as incoming edges to
         * the [Network.Builder].
         *
         * @param validatedTarget validated certificate
         */
        private fun indexIncomingEdges(validatedTarget: KeyRingInfo) {
            val validatedTargetKeyRing = KeyRingUtils.publicKeys(validatedTarget.keys)
            val targetFingerprint = Fingerprint(OpenPgpFingerprint.of(validatedTargetKeyRing))
            val targetPrimaryKey = validatedTargetKeyRing.publicKey!!
            val target = nodeMap[targetFingerprint] ?: return // skip over expired keys for now :/

            // Direct-Key Signatures (delegations) by X on Y
            val delegations = SignatureUtils.getDelegations(validatedTargetKeyRing)
            for (delegation in delegations) {
                processDelegation(targetPrimaryKey, target, delegation)
            }

            // EdgeComponent Signatures by X on Y over user-ID U
            val userIds = targetPrimaryKey.userIDs
            while (userIds.hasNext()) {
                val userId = userIds.next()
                // There are potentially multiple certifications per user-ID
                val userIdSigs = SignatureUtils.get3rdPartyCertificationsFor(
                        userId, validatedTargetKeyRing)
                userIdSigs.forEach {
                    processCertificationOnUserId(targetPrimaryKey, target, userId, it)
                }
            }
        }

        /**
         * Process a delegation signature (direct-key signature issued by a third-party certificate)
         * and add it upon successful verification as an edge to the [Network.Builder].
         *
         * @param targetPrimaryKey public primary key of the target certificate
         * @param target target certificate node
         * @param delegation delegation signature
         */
        private fun processDelegation(targetPrimaryKey: PGPPublicKey,
                                      target: Node,
                                      delegation: PGPSignature) {
            // There might be more than one cert with a subkey of matching key-id
            val issuerCandidates = byKeyId[delegation.keyID]
                    ?: return // missing issuer cert

            for (candidate in issuerCandidates) {
                val issuerKeyRing = KeyRingUtils.publicKeys(candidate.keys)
                val issuerFingerprint = Fingerprint(OpenPgpFingerprint.of(issuerKeyRing))
                val issuerSigningKey = issuerKeyRing.getPublicKey(delegation.keyID)!!
                val issuer = nodeMap[issuerFingerprint]!!

                try {
                    // Check signature type
                    SignatureValidator.signatureIsOfType(SignatureType.KEY_REVOCATION, SignatureType.DIRECT_KEY).verify(delegation)
                    // common verification steps that are shared by delegations and certifications
                    verifyCommonSignatureCriteria(candidate, delegation, issuerSigningKey, targetPrimaryKey, policy)
                    // check signature correctness
                    SignatureValidator.correctSignatureOverKey(issuerSigningKey, targetPrimaryKey).verify(delegation)
                    // only add the edge if the above checks did not throw
                    networkBuilder.addEdge(fromDelegation(issuer, target, delegation))
                    return // we're done
                } catch (e: SignatureValidationException) {
                    val targetFingerprint = OpenPgpFingerprint.of(targetPrimaryKey)
                    LOGGER.warn("Cannot verify signature by $issuerFingerprint" +
                            " on cert of $targetFingerprint", e)
                }
            }
        }

        /**
         * Process a certification (third-party-issued certification over the given [userId])
         * and add it upon successful verification as an edge to the [Network.Builder].
         *
         * @param targetPrimaryKey public primary key of the target certificate
         * @param target target certificate node
         * @param userId target user-id over which the [certification] is calculated
         * @param certification certification signature
         */
        private fun processCertificationOnUserId(targetPrimaryKey: PGPPublicKey,
                                                 target: Node,
                                                 userId: String,
                                                 certification: PGPSignature) {
            // There might be more than one cert with a subkey of matching key-id
            val issuerCandidates = byKeyId[certification.keyID]
                    ?: return // missing issuer cert

            for (candidate in issuerCandidates) {
                val issuerKeyRing = KeyRingUtils.publicKeys(candidate.keys)
                val issuerFingerprint = Fingerprint(OpenPgpFingerprint.of(issuerKeyRing))
                val issuerSigningKey = issuerKeyRing.getPublicKey(certification.keyID)!!
                val issuer = nodeMap[issuerFingerprint]!!

                try {
                    // check signature type
                    SignatureValidator.signatureIsOfType(
                            SignatureType.CERTIFICATION_REVOCATION, SignatureType.GENERIC_CERTIFICATION,
                            SignatureType.NO_CERTIFICATION, SignatureType.CASUAL_CERTIFICATION,
                            SignatureType.POSITIVE_CERTIFICATION).verify(certification)
                    // perform shared verification steps
                    verifyCommonSignatureCriteria(candidate, certification, issuerSigningKey, targetPrimaryKey, policy)
                    // check correct signature
                    SignatureValidator.correctSignatureOverUserId(userId, targetPrimaryKey, issuerSigningKey).verify(certification)
                    // Only add the edge, if the above checks did not throw
                    networkBuilder.addEdge(fromCertification(issuer, target, userId, certification))
                    return // we're done
                } catch (e: SignatureValidationException) {
                    LOGGER.warn("Cannot verify signature for '$userId' by $issuerFingerprint" +
                            " on cert of ${target.fingerprint}", e)
                }
            }
        }

        fun verifyCommonSignatureCriteria(issuer: KeyRingInfo,
                                          signature: PGPSignature,
                                          signingKey: PGPPublicKey,
                                          signedKey: PGPPublicKey,
                                          policy: Policy): Boolean {
            // Check for general "well-formed-ness" (has legal creation time)
            SignatureValidator.signatureIsNotMalformed(signingKey).verify(signature)
            // Check for unknown critical notations or subpackets
            if (signature.version >= 4) {
                SignatureValidator.signatureDoesNotHaveCriticalUnknownNotations(policy.notationRegistry).verify(signature)
                SignatureValidator.signatureDoesNotHaveCriticalUnknownSubpackets().verify(signature)
            }
            // check for signature effectiveness at reference time (was created before reference time, is not expired)
            SignatureValidator.signatureIsEffective(referenceTime).verify(signature)
            // check if signature is not invalidated by hard-revoked cert
            if (issuer.revocationState == org.pgpainless.algorithm.RevocationState.hardRevoked()) {
                // cert is hard revoked
                throw SignatureValidationException("Signature is invalid because certificate ${issuer.fingerprint} is hard revoked.")
            }
            // check if signature is not invalidated by soft-revoked cert
            if (issuer.revocationState.isSoftRevocation) {
                SignatureValidator.signatureWasCreatedInBounds(issuer.creationDate, issuer.revocationDate).verify(signature)
            }
            // check if signature is not invalidated by expired primary key
            val exp = issuer.primaryKeyExpirationDate
            if (exp != null) {
                SignatureValidator.signatureWasCreatedInBounds(issuer.creationDate, exp).verify(signature)
            }
            // check signature algorithms against our algorithm policy
            SignatureValidator.signatureUsesAcceptableHashAlgorithm(policy).verify(signature)
            SignatureValidator.signatureUsesAcceptablePublicKeyAlgorithm(policy, signingKey).verify(signature)

            // check if signature is not created before the target key
            SignatureValidator.signatureDoesNotPredateSignee(signedKey).verify(signature)

            return true
        }

        /**
         * Map an [OpenPgpFingerprint] to a [Identifier].
         *
         * @param fingerprint [OpenPgpFingerprint]
         */
        private fun Fingerprint(fingerprint: OpenPgpFingerprint) = Identifier(fingerprint.toString())

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
            @JvmStatic
            private val LOGGER = LoggerFactory.getLogger(PGPNetworkFactory::class.java)

            /**
             * Create a [PGPNetworkFactory] from a [Sequence] of [Certificates][Certificate].
             * This method validates the certificates and then creates a [PGPNetworkFactory] from them.
             *
             * @param certificates certificates, e.g. acquired from a [PGPCertificateStore]
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for network evaluation
             */
            @JvmStatic
            fun fromCertificates(certificates: Sequence<Certificate>,
                                 policy: Policy,
                                 referenceTime: Date): PGPNetworkFactory {
                return fromValidCertificates(
                        parseValidCertificates(certificates, policy, referenceTime),
                        policy,
                        referenceTime
                )
            }

            /**
             * Create a [PGPNetworkFactory] from a list of [validated certificates][KeyRingInfo].
             *
             * @param certificates already validated certificates
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for network evaluation
             */
            @JvmStatic
            fun fromValidCertificates(certificates: List<KeyRingInfo>,
                                      policy: Policy,
                                      referenceTime: Date): PGPNetworkFactory {
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
            private fun parseValidCertificates(certificates: Sequence<Certificate>,
                                               policy: Policy,
                                               referenceTime: Date): List<KeyRingInfo> {
                return certificates
                        .mapNotNull {
                            try { PGPainless.readKeyRing().publicKeyRing(it.inputStream) }
                            catch (e: IOException) { null }
                        }
                        .map { KeyRingInfo(it, policy, referenceTime) }
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
            val revocationReason = SignatureSubpacketsUtil.getRevocationReason(revocation)
                    ?: return RevocationState.hardRevoked()
            return if (RevocationAttributes.Reason.isHardRevocation(revocationReason.revocationReason))
                RevocationState.hardRevoked()
            else
                RevocationState.softRevoked(revocation.creationTime)
        }
    }
}
