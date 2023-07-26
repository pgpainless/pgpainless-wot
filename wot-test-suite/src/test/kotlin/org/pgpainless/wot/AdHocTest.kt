// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.junit.jupiter.api.Test
import org.pgpainless.wot.api.WebOfTrustAPI
import org.pgpainless.wot.network.TrustRoot
import java.util.*
import kotlin.test.assertTrue

class AdHocTest: PGPDSL {

    @Test
    fun test() {
        val vectors = AdHocVectors.BestViaRoot()
        val store = vectors.pgpCertificateStore
        val network = PGPNetworkParser(store).buildNetwork()

        val api = WebOfTrustAPI(network, setOf(TrustRoot(vectors.aliceFingerprint)),
                false, false, 120, Date(),
                DijkstraAlgorithmFactory())
        assertTrue { api.authenticate(vectors.targetFingerprint, vectors.targetUID, false).acceptable }
    }
}