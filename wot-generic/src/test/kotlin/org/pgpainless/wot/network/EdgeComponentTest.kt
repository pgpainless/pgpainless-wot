// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dsl.NetworkDSL
import java.util.*
import kotlin.test.assertEquals

class EdgeComponentTest: NetworkDSL {

    private val alice = Node(
            Identifier("A"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Alice <alice@pgpainless.org>", RevocationState.notRevoked())))
    private val bob = Node(
            Identifier("B"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Bob <bob@example.org>", RevocationState.notRevoked())))
    private val charlie = Node(
            Identifier("C"),
            null,
            RevocationState.notRevoked(),
            mapOf())

    @Test
    fun `verify result of toString() on certification signature`() {
        val edgeComponent = Certification(alice, bob, "Bob <bob@example.org>", Date())
        assertEquals("A certifies binding: Bob <bob@example.org> <-> B [120]",
                edgeComponent.toString())
    }

    @Test
    fun `verify result of toString() on delegation signature`() {
        val delegation = Delegation(alice, bob, Date())
        assertEquals("A certifies binding: null <-> B [120]",
                delegation.toString())
    }
}