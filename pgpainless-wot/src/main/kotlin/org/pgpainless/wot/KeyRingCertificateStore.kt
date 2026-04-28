// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import java.io.InputStream
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.PGPainless
import org.pgpainless.certificate_store.CertificateFactory
import org.pgpainless.key.OpenPgpFingerprint
import pgp.certificate_store.PGPCertificateStore
import pgp.certificate_store.certificate.Certificate
import pgp.certificate_store.certificate.KeyMaterialMerger
import pgp.certificate_store.exception.BadNameException
import java.io.File

/**
 * Implementation of [PGPCertificateStore] which is based on one or more lists of
 * [OpenPGPCertificate]s. During initialization, all items in the lists are converted into
 * [Certificates][Certificate] and stored in a map keyed by their fingerprints.
 *
 * In case of fingerprint collisions across certificates from different collections, [Certificate]
 * objects from a list of OpenPGPCertificates with a higher list index take precedence.
 *
 * [Certificates][Certificate] being inserted using [insertCertificate] or
 * [insertCertificateBySpecialName] are also stored in that map, but are not being written into base
 * list.
 */
class KeyRingCertificateStore(baseCertificates: List<List<OpenPGPCertificate>>) :
    PGPCertificateStore {

    // Keep certificates inserted only in memory
    private val certificates = mutableMapOf<String, Certificate>()
    private val api = PGPainless.getInstance()

    init {
        baseCertificates.forEach { store ->
            store.forEach {
                val fingerprint = OpenPgpFingerprint.of(it).toString()
                val certificate = CertificateFactory.certificateFromOpenPGPCertificate(it, null)
                certificates[fingerprint] = certificate
            }
        }
    }

    constructor(
        baseKeyRing: PGPPublicKeyRingCollection
    ) : this(listOf(baseKeyRing.map { PGPainless.getInstance().toCertificate(it) }.toList()))

    override fun getCertificate(identifier: String?): Certificate {
        if (identifier == null) {
            throw BadNameException("Identifier MUST NOT be null.")
        }

        return certificates.getOrElse(identifier) {
            throw NoSuchElementException("No certificate for identifier $identifier found.")
        }
    }

    override fun getCertificateIfChanged(identifier: String?, tag: Long?): Certificate {
        return getCertificate(identifier) // TODO: Implement properly
    }

    override fun getCertificatesBySubkeyId(subkeyId: Long): MutableIterator<Certificate> {
        return certificates.values
            .filter { it.subkeyIds.contains(subkeyId) }
            .toMutableList()
            .listIterator()
    }

    override fun insertCertificate(data: InputStream?, merge: KeyMaterialMerger?): Certificate {
        val publicKeys = api.readKey().parseCertificate(data!!)
        val certificate = CertificateFactory.certificateFromOpenPGPCertificate(publicKeys!!, null)
        val insert: Certificate? =
            if (merge != null) {
                val existing =
                    try {
                        getCertificate(certificate.fingerprint)
                    } catch (e: NoSuchElementException) {
                        null
                    }
                merge.merge(certificate, existing).asCertificate()
            } else {
                certificate
            }

        if (insert == null) {
            return certificate
        }

        certificates[insert.fingerprint] = insert
        return insert
    }

    override fun insertCertificateBySpecialName(
        specialName: String?,
        data: InputStream?,
        merge: KeyMaterialMerger?
    ): Certificate {
        val publicKeys = api.readKey().parseCertificate(data!!)
        val certificate = CertificateFactory.certificateFromOpenPGPCertificate(publicKeys!!, null)

        val insert: Certificate? =
            if (merge != null) {
                val existing =
                    try {
                        getCertificate(specialName!!)
                    } catch (e: NoSuchElementException) {
                        null
                    }
                merge.merge(certificate, existing).asCertificate()
            } else {
                certificate
            }

        if (insert == null) {
            return certificate
        }

        certificates[specialName!!] = insert
        return insert
    }

    override fun getCertificates(): MutableIterator<Certificate> {
        return certificates.values.iterator()
    }

    override fun getFingerprints(): MutableIterator<String> {
        return certificates.values.map { it.fingerprint }.toMutableList().listIterator()
    }

    companion object {
        @JvmStatic
        fun fromFiles(files: Array<File>): KeyRingCertificateStore {
            return KeyRingCertificateStore(
                files.map {
                    PGPainless.getInstance().readKey().parseCertificates(it.inputStream())
                })
        }
    }
}
