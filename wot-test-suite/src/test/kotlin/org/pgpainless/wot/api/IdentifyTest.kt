// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.pgpainless.wot.api

import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.wot.DijkstraAlgorithmFactory
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.PGPNetworkParser
import org.pgpainless.wot.network.TrustRoot
import org.sequoia_pgp.wot.vectors.BestViaRootVectors
import kotlin.test.assertEquals

class IdentifyTest {

    @Test
    fun `best-via-root - verify that we can identify target`() {
        val v = BestViaRootVectors()
        val keyRing = PGPainless.readKeyRing().publicKeyRingCollection(v.keyRingInputStream())
        val store = KeyRingCertificateStore(keyRing)
        val network = PGPNetworkParser(store).buildNetwork(referenceTime = v.t1)

        val roots = setOf(TrustRoot(v.aliceFpr))
        val api = WebOfTrustAPI(network, roots, false, false, 120, v.t1,
                DijkstraAlgorithmFactory())

        val result = api.identify(v.targetFpr)
        assertEquals(v.targetUid, result.bindings[0].userId)
    }
}