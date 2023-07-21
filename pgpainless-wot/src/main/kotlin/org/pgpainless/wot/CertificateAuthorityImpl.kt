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
import org.pgpainless.wot.api.*
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.ReferenceTime
import org.pgpainless.wot.network.Roots
import pgp.certificate_store.PGPCertificateStore
import java.util.*

/**
 * Implementation of PGPainless' [CertificateAuthority] using pgpainless-wot.
 *
 * @param network Flow-Network, e.g. from [WebOfTrust.buildNetwork].
 * @param trustRoots some trust anchors
 * @param certificateStore certificate store to extract certificates for path nodes from
 */
class CertificateAuthorityImpl(private val network: Network,
                               private val trustRoots: Roots,
                               private val certificateStore: PGPCertificateStore):
    CertificateAuthority {

    override fun authenticate(fingerprint: OpenPgpFingerprint, userId: String, email: Boolean, referenceTime: Date, targetAmount: Int): CertificateAuthenticity {
        val api = WoTAPI(network, trustRoots, gossip = false, certificationNetwork = false,
            targetAmount, ReferenceTime.timestamp(referenceTime))
        val result = api.authenticate(AuthenticateAPI.Arguments(Fingerprint(fingerprint.toString()), userId, email))

        return mapToAuthenticity(result.binding, targetAmount)
    }

    override fun lookup(userId: String, email: Boolean, referenceTime: Date, targetAmount: Int): List<CertificateAuthenticity> {
        val api = WoTAPI(network, trustRoots, gossip = false, certificationNetwork = false,
            targetAmount, ReferenceTime.timestamp(referenceTime))
        val result = api.lookup(LookupAPI.Arguments(userId, email))
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

    private fun readPublicKeyRing(fingerprint: Fingerprint): PGPPublicKeyRing {
        val certificate = certificateStore.getCertificate(fingerprint.toString())
        return PGPainless.readKeyRing().publicKeyRing(certificate.inputStream)!!
    }
}