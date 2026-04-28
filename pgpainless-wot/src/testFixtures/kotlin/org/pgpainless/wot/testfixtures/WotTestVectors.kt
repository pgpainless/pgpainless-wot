// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.testfixtures

import java.io.IOException
import java.io.InputStream
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.Trustworthiness
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.CertificationSubpackets
import org.pgpainless.util.Passphrase

class WotTestVectors {

    companion object {

        @JvmStatic
        fun getTestResource(resource: String): InputStream {
            val input = WotTestVectors::class.java.classLoader.getResourceAsStream(resource)
            return requireNotNull(input) { "Unknown resource $resource" }
        }

        @JvmStatic
        val freshFooBankCaKey: OpenPGPKey =
            PGPainless.getInstance()
                .readKey()
                .parseKey(getTestResource("test_vectors/freshly_generated/foobankCaKey.asc"))!!

        @JvmStatic
        val freshFooBankCaCert: OpenPGPCertificate =
            PGPainless.getInstance()
                .readKey()
                .parseCertificate(
                    getTestResource("test_vectors/freshly_generated/foobankCaCert.asc"))!!

        @JvmStatic val fooBankCaPassphrase = "superS3cureP4ssphrase"

        @JvmStatic
        val fooBankCaProtector: SecretKeyRingProtector =
            SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(fooBankCaPassphrase))

        @JvmStatic
        val freshFooBankEmployeeKey: OpenPGPKey =
            PGPainless.getInstance()
                .readKey()
                .parseKey(
                    getTestResource("test_vectors/freshly_generated/foobankEmployeeKey.asc"))!!

        @JvmStatic
        val freshFooBankEmployeeCert: OpenPGPCertificate =
            PGPainless.getInstance()
                .readKey()
                .parseCertificate(
                    getTestResource("test_vectors/freshly_generated/foobankEmployeeCert.asc"))!!

        @JvmStatic val fooBankEmployeePassphrase = "iLoveWorking@FooBank"

        @JvmStatic
        val fooBankEmployeeProtector: SecretKeyRingProtector =
            SecretKeyRingProtector.unlockAnyKeyWith(
                Passphrase.fromPassword(fooBankEmployeePassphrase))

        @JvmStatic
        val freshFooBankAdminKey: OpenPGPKey =
            PGPainless.getInstance()
                .readKey()
                .parseKey(getTestResource("test_vectors/freshly_generated/foobankAdminKey.asc"))!!

        @JvmStatic
        val freshFooBankAdminCert: OpenPGPCertificate =
            PGPainless.getInstance()
                .readKey()
                .parseCertificate(
                    getTestResource("test_vectors/freshly_generated/foobankAdminCert.asc"))!!

        @JvmStatic val fooBankAdminPassphrase = "keepFooBankSecure"

        @JvmStatic
        val fooBankAdminProtector: SecretKeyRingProtector =
            SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(fooBankAdminPassphrase))

        @JvmStatic
        val freshFooBankCustomerKey: OpenPGPKey =
            PGPainless.getInstance()
                .readKey()
                .parseKey(
                    getTestResource("test_vectors/freshly_generated/foobankCustomerKey.asc"))!!

        @JvmStatic
        val freshFooBankCustomerCert: OpenPGPCertificate =
            PGPainless.getInstance()
                .readKey()
                .parseCertificate(
                    getTestResource("test_vectors/freshly_generated/foobankCustomerCert.asc"))!!

        @JvmStatic
        val fooBankCustomerProtector: SecretKeyRingProtector =
            SecretKeyRingProtector.unprotectedKeys()

        @JvmStatic
        val freshBarBankCaKey: OpenPGPKey =
            PGPainless.getInstance()
                .readKey()
                .parseKey(getTestResource("test_vectors/freshly_generated/barbankCaKey.asc"))!!

        @JvmStatic
        val freshBarBankCaCert: OpenPGPCertificate =
            PGPainless.getInstance()
                .readKey()
                .parseCertificate(
                    getTestResource("test_vectors/freshly_generated/barbankCaCert.asc"))!!

        @JvmStatic
        val barBankCaProtector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()

        @JvmStatic
        val freshBarBankEmployeeKey: OpenPGPKey =
            PGPainless.getInstance()
                .readKey()
                .parseKey(
                    getTestResource("test_vectors/freshly_generated/barbankEmployeeKey.asc"))!!

        @JvmStatic
        val freshBarBankEmployeeCert: OpenPGPCertificate =
            PGPainless.getInstance()
                .readKey()
                .parseCertificate(
                    getTestResource("test_vectors/freshly_generated/barbankEmployeeCert.asc"))!!

        @JvmStatic
        val freshFakeFooBankEmployeeKey: OpenPGPKey =
            PGPainless.getInstance()
                .readKey()
                .parseKey(
                    getTestResource("test_vectors/freshly_generated/fakeFoobankEmployeeKey.asc"))!!

        @JvmStatic
        val freshFakeFooBankEmployeeCert: OpenPGPCertificate =
            PGPainless.getInstance()
                .readKey()
                .parseCertificate(
                    getTestResource("test_vectors/freshly_generated/fakeFoobankEmployeeCert.asc"))!!

        @Throws(IOException::class)
        fun getCrossSignedBarBankCaCert(): OpenPGPCertificate {
            return PGPainless.getInstance()
                .readKey()
                .parseCertificate(getTestResource("cross_signed/barbankCaCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedBarBankEmployeeCert(): OpenPGPCertificate {
            return PGPainless.getInstance()
                .readKey()
                .parseCertificate(getTestResource("cross_signed/barbankEmployeeCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedFooBankAdminCert(): OpenPGPCertificate {
            return PGPainless.getInstance()
                .readKey()
                .parseCertificate(getTestResource("cross_signed/foobankAdminCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedFooBankCaCert(): OpenPGPCertificate {
            return PGPainless.getInstance()
                .readKey()
                .parseCertificate(getTestResource("cross_signed/foobankCaCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedFooBankEmployeeCert(): OpenPGPCertificate {
            return PGPainless.getInstance()
                .readKey()
                .parseCertificate(getTestResource("cross_signed/foobankEmployeeCert.asc"))
        }

        // Generate cross signed test vectors from freshly generated
        @Throws(IOException::class, PGPException::class)
        fun crossSign() {
            val fooBankRegex = "<[^>]+[@.]foobank\\.com>$"
            val barBankRegex = "<[^>]+[@.]barbank\\.com>$"

            // Foo CA signs Foo Employee
            val caCertifiedFooBankEmployeeCert =
                PGPainless.getInstance()
                    .generateCertification()
                    .certifyUserId(
                        "Foo Bank Employee <employee@foobank.com>", freshFooBankEmployeeCert)
                    .withKey(freshFooBankCaKey, fooBankCaProtector)
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.addNotationData(
                                    false, "affiliation@foobank.com", "employee")
                            }
                        })
                    .certifiedCertificate

            // Foo CA signs Foo Admin
            val caCertifiedFooBankAdminCert =
                PGPainless.getInstance()
                    .generateCertification()
                    .certifyUserId("Foo Bank Admin <admin@foobank.com>", freshFooBankAdminCert)
                    .withKey(freshFooBankCaKey, fooBankCaProtector)
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.addNotationData(
                                    false, "affiliation@foobank.com", "administrator")
                            }
                        })
                    .certifiedCertificate

            // Foo Employee delegates trust to Foo CA
            val employeeDelegatedCaCert =
                PGPainless.getInstance()
                    .generateCertification()
                    .delegateTrust(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankEmployeeKey, fooBankEmployeeProtector)
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.setRegularExpression(fooBankRegex)
                            }
                        })
                    .certifiedCertificate

            // Foo Admin delegates trust to Foo CA
            val adminDelegatedCaCert =
                PGPainless.getInstance()
                    .generateCertification()
                    .delegateTrust(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankAdminKey, fooBankAdminProtector)
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.setRegularExpression(fooBankRegex)
                            }
                        })
                    .certifiedCertificate

            // Customer delegates trust to Foo CA
            val customerDelegatedCaCert =
                PGPainless.getInstance()
                    .generateCertification()
                    .delegateTrust(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankCustomerKey, SecretKeyRingProtector.unprotectedKeys())
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.setRegularExpression(fooBankRegex)
                            }
                        })
                    .certifiedCertificate
            var mergedFooCa =
                PGPainless.getInstance()
                    .mergeCertificate(employeeDelegatedCaCert, adminDelegatedCaCert)
            mergedFooCa =
                PGPainless.getInstance().mergeCertificate(mergedFooCa, customerDelegatedCaCert)

            // Foo Admin delegates trust to Bar CA
            val fooAdminDelegatedBarCa =
                PGPainless.getInstance()
                    .generateCertification()
                    .delegateTrust(freshBarBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankAdminKey, fooBankAdminProtector)
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.setRegularExpression("<[^>]+[@.]barbank\\.com>$")
                            }
                        })
                    .certifiedCertificate

            // Bar Employee delegates Bar CA
            val barEmployeeDelegatesBarCa =
                PGPainless.getInstance()
                    .generateCertification()
                    .delegateTrust(freshBarBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshBarBankEmployeeKey, SecretKeyRingProtector.unprotectedKeys())
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.setRegularExpression(barBankRegex)
                            }
                        })
                    .certifiedCertificate
            val mergedBarCa =
                PGPainless.getInstance()
                    .mergeCertificate(fooAdminDelegatedBarCa, barEmployeeDelegatesBarCa)

            // Bar CA signs Bar Employee
            val barCaCertifiedEmployeeCert =
                PGPainless.getInstance()
                    .generateCertification()
                    .certifyUserId(
                        "Bar Bank Employee <employee@barbank.com>", freshBarBankEmployeeCert)
                    .withKey(freshBarBankCaKey, SecretKeyRingProtector.unprotectedKeys())
                    .buildWithSubpackets(
                        object : CertificationSubpackets.Callback {
                            override fun modifyHashedSubpackets(
                                hashedSubpackets: CertificationSubpackets
                            ) {
                                hashedSubpackets.addNotationData(
                                    false, "affiliation@barbank.com", "employee")
                            }
                        })
                    .certifiedCertificate

            // CHECKSTYLE:OFF
            println("Foo Employee")
            println(PGPainless.asciiArmor(caCertifiedFooBankEmployeeCert))
            println("Foo Admin")
            println(PGPainless.asciiArmor(caCertifiedFooBankAdminCert))
            println("Foo CA")
            println(PGPainless.asciiArmor(mergedFooCa))
            println("Bar CA")
            println(PGPainless.asciiArmor(mergedBarCa))
            println("Bar Employee")
            println(PGPainless.asciiArmor(barCaCertifiedEmployeeCert))
            // CHECKSTYLE:ON
        }
    }
}
