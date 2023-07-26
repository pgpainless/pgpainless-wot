// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.dsl.NetworkDSL
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EdgeTest: NetworkDSL {

    private val alice = Node(Identifier("A"), null, RevocationState.notRevoked(), mapOf())
    private val bob = Node(Identifier("B"), null, RevocationState.notRevoked(), mapOf())
    private val charlie = Node(Identifier("C"), null, RevocationState.notRevoked(), mapOf())

    private val aliceSignsBob = Delegation(alice, bob, Date())
    private val aliceSignsBobUserId = Certification(alice, bob, "Bob <bob@example.org>", Date())
    private val aliceSignsCharlie = Delegation(alice, charlie, Date())
    private val charlieSignsBob = Delegation(charlie, bob, Date())

    @Test
    fun `verify that properties of an empty edge are also empty`() {
        val empty = Edge(alice, bob)
        assert(empty.components().isEmpty())
        assertEquals(alice, empty.issuer)
        assertEquals(bob, empty.target)
    }

    @Test
    fun `verify that add()ing edge components works if issuer and target match that of the edge`() {
        val set = Edge(alice, bob)

        set.addComponent(aliceSignsBob)
        assertTrue {
            set.components().any { it.value.contains(aliceSignsBob) }
        }
        set.addComponent(aliceSignsBobUserId)
        assertTrue {
            set.components()["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId)
        }
    }

    @Test
    fun `verify that add()ing another component fails if the issuer mismatches`() {
        val set = Edge(alice, bob)
        assertThrows<IllegalArgumentException> { set.addComponent(charlieSignsBob) }
    }

    @Test
    fun `verify that add()ing another component fails if the target mismatches`() {
        val set = Edge(alice, bob)
        assertThrows<IllegalArgumentException> { set.addComponent(aliceSignsCharlie) }
    }

    @Test
    fun `verify that merge()ing another edge works if issuer and target match that of the edge`() {
        val set = Edge(aliceSignsBob)
        val others = Edge(aliceSignsBobUserId)

        set.join(others)
        assertEquals(2, set.components().size)
        assertTrue { set.components()[null]!!.contains(aliceSignsBob) }
        assertTrue { set.components()["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId) }
    }

    @Test
    fun `verify that merge()ing another edge with mismatched issuer fails`() {
        val set = Edge(aliceSignsBob)
        val issuerMismatch = Edge(charlieSignsBob)

        assertThrows<IllegalArgumentException> { set.join(issuerMismatch) }
    }

    @Test
    fun `verify that merge()ing another edge with mismatched target fails`() {
        val set = Edge(aliceSignsBob)
        val targetMismatch = Edge(aliceSignsCharlie)

        assertThrows<IllegalArgumentException> { set.join(targetMismatch) }
    }

    @Test
    fun `verify that merge()ing an edge with itself is idempotent`() {
        val set = Edge(aliceSignsBob)
        assertEquals(1, set.components().size)
        set.join(set)
        assertEquals(1, set.components().size)
    }

    @Test
    fun `verify that toString() of an empty edge is the empty string`() {
        val empty = Edge(alice, bob)
        assertEquals("", empty.toString())
    }

    @Test
    fun `verify that toString() of a edge with two components matches our expectations`() {
        val twoCerts = Edge(aliceSignsBob)
        twoCerts.addComponent(aliceSignsBobUserId)

        assertEquals("A certifies binding: Bob <bob@example.org> <-> B [120]\n" +
                "A certifies binding: null <-> B [120]\n", twoCerts.toString())
    }
    
    @Test
    fun `verify that for multiple components over the same datum, only the most recent components are preserved`() {
        val now = Date()
        val fiveSecondsBefore = Date(now.time - 5000)
        val old = Certification(alice, bob, "Bob <bob@example.org>", fiveSecondsBefore)
        val new = Certification(alice, bob, "Bob <bob@example.org>", now)
        val new2 = Edge.Certification(alice, bob, "Bob <bob@example.org>", now, null, true, 44, TrustDepth.auto(10))

        var set = Edge(alice, bob)
        set.addComponent(old)

        assertEquals(listOf(old), set.components()["Bob <bob@example.org>"])

        set.addComponent(new)
        assertEquals(listOf(new), set.components()["Bob <bob@example.org>"])

        set.addComponent(new2)
        assertEquals(listOf(new, new2), set.components()["Bob <bob@example.org>"])

        set.addComponent(old)
        assertEquals(listOf(new, new2), set.components()["Bob <bob@example.org>"])
    }
}