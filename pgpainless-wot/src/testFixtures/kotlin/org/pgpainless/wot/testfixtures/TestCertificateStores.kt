// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.testfixtures

import org.opentest4j.TestAbortedException
import org.pgpainless.certificate_store.KeyMaterialReader
import pgp.cert_d.PGPCertificateDirectory
import pgp.cert_d.backend.InMemoryCertificateDirectoryBackend
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookup
import pgp.certificate_store.certificate.KeyMaterialMerger
import java.io.InputStream

class TestCertificateStores {
    companion object {
        @JvmStatic
        private val merger: KeyMaterialMerger = KeyMaterialMerger { data, _ -> data }  // Always use newer material

        @JvmStatic
        fun disconnectedGraph(): PGPCertificateDirectory {
            return createInMemoryCertificateDirectory().apply {
                insertTrustRoot(getTestVector("cross_signed/foobankCaCert.asc"), merger)
                insert(getTestVector("cross_signed/foobankEmployeeCert.asc"), merger)
                insert(getTestVector("cross_signed/foobankAdminCert.asc"), merger)
                insert(getTestVector("cross_signed/barbankCaCert.asc"), merger)
                insert(getTestVector("cross_signed/barbankEmployeeCert.asc"), merger)
            }
        }

        @JvmStatic
        fun emptyGraph() = createInMemoryCertificateDirectory()

        @JvmStatic
        fun oneDelegationGraph(): PGPCertificateDirectory {
            return createInMemoryCertificateDirectory().apply {
                insert(getTestVector("cross_signed/foobankAdminCert.asc"), merger)
                insert(getTestVector("cross_signed/barbankCaCert.asc"), merger)
            }
        }

        @JvmStatic
        fun anomalyGraph(): PGPCertificateDirectory {
            return createInMemoryCertificateDirectory().apply {
                insert(getTestVector("anomalies/felix.pub"), merger)
            }
        }

        @JvmStatic
        private fun createInMemoryCertificateDirectory(): PGPCertificateDirectory {
            return PGPCertificateDirectory(
                InMemoryCertificateDirectoryBackend(KeyMaterialReader()),
                InMemorySubkeyLookup())
        }

        @JvmStatic
        private fun getTestVector(testVectorName: String): InputStream {
            return requireResource("test_vectors/$testVectorName")
        }

        @JvmStatic
        private fun requireResource(resourceName: String): InputStream {
            return TestCertificateStores::class.java.classLoader.getResourceAsStream(resourceName)
                ?: throw TestAbortedException("Cannot read resource $resourceName: InputStream is null.")
        }
    }
}