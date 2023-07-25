// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.junit.jupiter.api.Test
import org.pgpainless.wot.api.WebOfTrustAPI
import org.pgpainless.wot.dsl.PGPDSL
import org.pgpainless.wot.network.ReferenceTime
import org.pgpainless.wot.network.Root
import org.pgpainless.wot.network.Roots
import org.pgpainless.wot.testfixtures.AdHocVectors
import kotlin.test.assertTrue

class AdHocTest: PGPDSL {

    @Test
    fun test() {
        val vectors = AdHocVectors.BestViaRoot()
        val store = vectors.pgpCertificateStore
        val network = PGPNetworkParser(store).buildNetwork()

        val api = WebOfTrustAPI(network, Roots(Root(vectors.aliceFingerprint)), false, false, 120, ReferenceTime.now())
        assertTrue { api.authenticate(vectors.targetFingerprint, vectors.targetUID, false).acceptable}
    }
}