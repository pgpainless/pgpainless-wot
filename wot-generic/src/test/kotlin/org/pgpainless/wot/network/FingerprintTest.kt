// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class FingerprintTest {

    @Test
    fun `verify that Fingerprint applies an uppercase() on the constructor argument`() {
        val fromLowerCase = Identifier("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", fromLowerCase.fingerprint)
    }


    @Test
    fun `verify that objects constructed from the lower- and uppercase representation do equal`() {
        val finger1 = Identifier("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        val finger2 = Identifier("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        assert(finger1 == finger2)
        assertEquals(finger1.hashCode(), finger2.hashCode())
    }

    @Test
    fun `verify the proper function of the equals() method and == operator`() {
        val finger1 = Identifier("0000000000000000000000000000000000000000")
        val finger2 = Identifier("1111111111111111111111111111111111111111")

        assertFalse { finger1.equals(null) }
        assert(finger1 == finger1)
        assert(finger1 != finger2)
        assertFalse { finger1.equals("2222222222222222222222222222222222222222") }
    }

    @Test
    fun `verify Fingerprints get sorted lexicographically`() {
        val list = mutableListOf(Identifier("A"), Identifier("C"), Identifier("B"))
        list.sort()

        assertEquals(
                listOf(Identifier("A"), Identifier("B"), Identifier("C")),
                list)
    }
}