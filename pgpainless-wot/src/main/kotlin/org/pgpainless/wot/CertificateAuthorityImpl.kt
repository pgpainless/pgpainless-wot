// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.pgpainless.PGPainless
import org.pgpainless.authentication.CertificateAuthenticity
import org.pgpainless.authentication.CertificateAuthenticity.CertificationChain
import org.pgpainless.authentication.CertificateAuthenticity.ChainLink
import org.pgpainless.authentication.CertificateAuthority
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.wot.api.Binding
import org.pgpainless.wot.api.WebOfTrustAPI
import org.pgpainless.wot.network.Identifier
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.TrustRoot
import org.pgpainless.wot.query.ShortestPathAlgorithmFactory
import pgp.certificate_store.PGPCertificateStore
import java.util.*

/**
 * Implementation of PGPainless' [CertificateAuthority] using pgpainless-wot.
 *
 * @param network Flow-Network, e.g. from [PGPNetworkParser.buildNetwork].
 * @param trustRoots some trust anchors
 * @param certificateStore certificate store to extract certificates for path nodes from
 */
class CertificateAuthorityImpl(private val network: Network,
                               private val trustRoots: Set<TrustRoot>,
                               private val certificateStore: PGPCertificateStore,
                               private val shortestPathAlgorithmFactory: ShortestPathAlgorithmFactory):
        CertificateAuthority {

    companion object {

        /**
         * Instantiate a [CertificateAuthority] using the Web of Trust.
         * It is advised to keep the result of this operation around for later reuse, since this method does
         * some heavy lifting.
         *
         * @param certificateStore certificate source
         * @param trustRoots some trust-roots
         * @param referenceTime reference time for trust calculations
         * @return certificate authority using the Web of Trust
         */
        @JvmStatic
        fun webOfTrustFromCertificateStore(
                certificateStore: PGPCertificateStore,
                trustRoots: Set<TrustRoot>,
                referenceTime: Date,
                shortestPathAlgorithmFactory: ShortestPathAlgorithmFactory): CertificateAuthorityImpl {
            val network = PGPNetworkParser(certificateStore).buildNetwork(referenceTime = referenceTime)
            return CertificateAuthorityImpl(network, trustRoots, certificateStore, shortestPathAlgorithmFactory)
        }
    }

    override fun authenticateBinding(fingerprint: OpenPgpFingerprint, userId: String, email: Boolean, referenceTime: Date, targetAmount: Int): CertificateAuthenticity {
        val api = WebOfTrustAPI(network, trustRoots, gossip = false, certificationNetwork = false,
                targetAmount, referenceTime, shortestPathAlgorithmFactory)
        val result = api.authenticate(Identifier(fingerprint.toString()), userId, email)

        return mapToAuthenticity(result.binding, targetAmount)
    }

    override fun lookupByUserId(userId: String, email: Boolean, referenceTime: Date, targetAmount: Int): List<CertificateAuthenticity> {
        val api = WebOfTrustAPI(network, trustRoots, gossip = false, certificationNetwork = false,
                targetAmount, referenceTime, shortestPathAlgorithmFactory)
        val result = api.lookup(userId, email)
        return result.bindings.map { mapToAuthenticity(it, targetAmount) }
    }

    override fun identifyByFingerprint(fingerprint: OpenPgpFingerprint, referenceTime: Date, targetAmount: Int): List<CertificateAuthenticity> {
        val api = WebOfTrustAPI(network, trustRoots, gossip = false, certificationNetwork = false,
                targetAmount, referenceTime, shortestPathAlgorithmFactory)
        val result = api.identify(Identifier(fingerprint.toString()))
        return result.bindings.map { mapToAuthenticity(it, targetAmount) }
    }

    private fun mapToAuthenticity(binding: Binding, targetAmount: Int): CertificateAuthenticity {
        val publicKeyRing = readPublicKeyRing(binding.fingerprint)

        val certificationChains = mutableMapOf<CertificationChain, Int>()
        for ((path, amount) in binding.paths.items) {
            val links = mutableListOf<ChainLink>()
            links.add(ChainLink(readPublicKeyRing(path.root.fingerprint)))

            for (edge in path.certifications) {
                val target = readPublicKeyRing(edge.target.fingerprint)
                links.add(ChainLink(target))
            }

            certificationChains[CertificationChain(path.amount, links)] = amount
        }

        return CertificateAuthenticity(publicKeyRing, binding.userId, certificationChains, targetAmount)
    }

    private fun readPublicKeyRing(fingerprint: Identifier): PGPPublicKeyRing {
        val certificate = certificateStore.getCertificate(fingerprint.toString())
        return PGPainless.readKeyRing().publicKeyRing(certificate.inputStream)!!
    }
}