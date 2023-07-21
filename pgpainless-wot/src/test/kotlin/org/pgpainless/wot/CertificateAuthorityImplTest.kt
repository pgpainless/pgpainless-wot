// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.util.io.Streams
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.OpenPgpV4Fingerprint
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Root
import org.pgpainless.wot.network.Roots
import org.pgpainless.wot.testfixtures.AdHocVectors
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CertificateAuthorityImplTest {

    val v = AdHocVectors.BestViaRoot()
    val store = KeyRingCertificateStore(v.publicKeyRingCollection)
    val network = WebOfTrust(store).buildNetwork()
    val trustRoots = Roots(Root(v.aliceFingerprint))

    val certAuthority = CertificateAuthorityImpl(network, trustRoots, store)

    @Test
    fun testSuccessfulAuthentication() {
        val authenticity = certAuthority.authenticate(OpenPgpV4Fingerprint(v.targetFingerprint.toString()), v.targetUID, false, Date(), 120)
        assertTrue { authenticity.isAuthenticated }
        assertEquals(v.targetFingerprint, Fingerprint(authenticity.certificate))
        assertEquals(
            listOf(v.aliceFingerprint, v.bobFingerprint, v.carolFingerprint, v.targetFingerprint),
            authenticity.certificationChains.keys.first().chainLinks.map {
                Fingerprint(it.certificate)
            })
    }

    @Test
    fun testUnsuccessfulAuthentication() {
        val authenticity = certAuthority.authenticate(OpenPgpV4Fingerprint(v.targetFingerprint.toString()), "Imposter <imposter@example.org>", false, Date() , 120)
        assertFalse { authenticity.isAuthenticated }
    }

    @Test
    fun encryptToAuthenticatableRecipients() {
        val output = ByteArrayOutputStream()
        val encryptionStream = PGPainless.encryptAndOrSign().onOutputStream(output).withOptions(
            ProducerOptions.encrypt(EncryptionOptions.encryptCommunications()
                .addAuthenticatableRecipients(v.targetUID, false, certAuthority, 120)))
        val msg = "Hello, World!\n"
        encryptionStream.write(msg.toByteArray())
        encryptionStream.close()

        val encResult = encryptionStream.result
        assertTrue { encResult.isEncryptedFor(v.targetCert) }
        assertFalse { encResult.isEncryptedFor(v.aliceCert) }
        assertFalse { encResult.isEncryptedFor(v.bobCert) }
        assertFalse { encResult.isEncryptedFor(v.carolCert) }
        assertFalse { encResult.isEncryptedFor(v.yellowCert) }
        assertFalse { encResult.isEncryptedFor(v.zebraCert) }

        val input = ByteArrayInputStream(output.toByteArray())
        val decryptionStream = PGPainless.decryptAndOrVerify()
            .onInputStream(input)
            .withOptions(ConsumerOptions.get()
                .addDecryptionKey(v.targetKey))
        val plaintext = ByteArrayOutputStream()
        Streams.pipeAll(decryptionStream, plaintext)
        decryptionStream.close()

        assertEquals(msg, plaintext.toString())
    }

    fun Fingerprint(publicKeyRing: PGPPublicKeyRing): Fingerprint {
        return Fingerprint(OpenPgpFingerprint.of(publicKeyRing).toString())
    }
}