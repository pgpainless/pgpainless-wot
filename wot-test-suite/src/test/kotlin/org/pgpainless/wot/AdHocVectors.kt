// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.CertificationSubpackets
import org.pgpainless.signature.subpackets.CertificationSubpackets.Callback
import org.pgpainless.wot.network.Identifier
import pgp.certificate_store.PGPCertificateStore

interface AdHocVectors {

    /**
     * When doing backwards propagation, we find paths from all nodes to the target. Since we don't
     * stop when we reach a root, the returned path should still be optimal. Consider:
     *
     * A --- 120/10 ---> B --- 120/10 ---> C --- 120/10 ---> Target \ / `--- 50/10 ---> Y --- 50/10
     * ---> Z --- 50/10 --------' When the root is B, then the path that we find for A should be A
     * -> B -> C -> Target, not A -> Y -> Z -> Target.
     */
    class BestViaRoot : AdHocVectors {
        val api = PGPainless.getInstance()
        val aliceUID: String = "Alice <alice@pgpainless.org>"
        val aliceKey: OpenPGPKey = api.generateKey().modernKeyRing(aliceUID)
        val aliceCert = aliceKey.toCertificate()
        val aliceFingerprint = Fingerprint(aliceKey)

        val bobUID = "Bob <bob@pgpainless.org>"
        val bobKey: OpenPGPKey = api.generateKey().simpleRsaKeyRing(bobUID, RsaLength._3072)
        val bobCert = bobKey.toCertificate()
        val bobFingerprint = Fingerprint(bobKey)

        val carolUID = "Carol <carol@example.com>"
        val carolKey: OpenPGPKey = api.generateKey().simpleEcKeyRing(carolUID)
        val carolCert = carolKey.toCertificate()
        val carolFingerprint = Fingerprint(carolKey)

        val targetUID = "Tanja <tanja@target.tld>"
        val targetKey: OpenPGPKey = api.generateKey().modernKeyRing(targetUID)
        val targetCert = targetKey.toCertificate()
        val targetFingerprint = Fingerprint(targetKey)

        val yellowUID = "Yellow <yellow@alternate.path>"
        val yellowKey: OpenPGPKey = api.generateKey().modernKeyRing(yellowUID)
        val yellowCert = yellowKey.toCertificate()
        val yellowFingerprint = Fingerprint(yellowKey)

        val zebraUID = "Zebra <zebra@alternate.path>"
        val zebraKey: OpenPGPKey = api.generateKey().modernKeyRing(zebraUID)
        val zebraCert = zebraKey.toCertificate()
        val zebraFingerprint = Fingerprint(zebraKey)

        override val publicKeyRingCollection: List<OpenPGPCertificate>

        init {
            publicKeyRingCollection =
                listOf(
                    targetCert
                        .let {
                            // C ---120/10--> Target
                            certify(issuer = carolKey, target = it, amount = 120, depth = 10)
                        }
                        .let {
                            // Z ---50/10---> Target
                            certify(issuer = zebraKey, target = it, amount = 50, depth = 10)
                        },
                    carolCert.let {
                        // B ---120/10--> C
                        certify(issuer = bobKey, target = it, amount = 120, depth = 10)
                    },
                    bobCert.let {
                        // A ---120/10--> B
                        certify(issuer = aliceKey, target = it, amount = 120, depth = 10)
                    },
                    aliceCert,
                    zebraCert.let {
                        // Y ---50/10--> Z
                        certify(issuer = yellowKey, target = it, amount = 50, depth = 10)
                    },
                    yellowCert.let {
                        // A ---50/10--> Y
                        certify(issuer = aliceKey, target = it, amount = 50, depth = 10)
                    })
        }
    }

    val publicKeyRingCollection: List<OpenPGPCertificate>

    val pgpCertificateStore: PGPCertificateStore
        get() = KeyRingCertificateStore(listOf(publicKeyRingCollection))

    fun certify(
        issuer: OpenPGPKey,
        target: OpenPGPCertificate,
        userId: String = target.allUserIds[0]!!.userId,
        amount: Int,
        depth: Int
    ): OpenPGPCertificate =
        PGPainless.getInstance()
            .generateCertification()
            .certifyUserId(userId, target)
            .withKey(issuer, SecretKeyRingProtector.unprotectedKeys())
            .buildWithSubpackets(
                object : Callback {
                    override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                        hashedSubpackets.setTrust(depth, amount)
                    }
                })
            .certifiedCertificate

    fun Fingerprint(cert: OpenPGPCertificate): Identifier =
        Identifier(OpenPgpFingerprint.of(cert).toString())
}
