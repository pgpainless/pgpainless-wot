// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.pgpainless.wot.api

import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.WebOfTrust
import org.pgpainless.wot.network.Root
import org.pgpainless.wot.network.Roots
import org.sequoia_pgp.wot.vectors.BestViaRootVectors
import kotlin.test.assertEquals

class LookupTest {

    @Test
    fun `best-via-root - verify that we can lookup the target`() {
        val v = BestViaRootVectors()
        val keyRing = PGPainless.readKeyRing().publicKeyRingCollection(v.keyRingInputStream())
        val store = KeyRingCertificateStore(keyRing)
        val network = WebOfTrust(store).buildNetwork(referenceTime = v.t1)

        val roots = Roots(Root(v.aliceFpr))
        val api = WoTAPI(network, roots, false, false, 120, v.t1)

        val byExactUserId = api.lookup(v.targetUid, false)
        assertEquals(v.targetFpr, byExactUserId.bindings[0].fingerprint)


        val byEmail = api.lookup(
                v.targetUid.replace("<", "").replace(">", ""), true)
        assertEquals(v.targetFpr, byEmail.bindings[0].fingerprint)
    }
}