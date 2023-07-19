// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.network.Depth
import org.pgpainless.wot.dsl.NetworkDSL
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PathTest : NetworkDSL {

    private val root = Node("aabbccddeeAABBCCDDEEaabbccddeeAABBCCDDEE")
    private val alice = Node("0000000000000000000000000000000000000000")
    private val bob = Node("1111111111111111111111111111111111111111")

    // Root -(255, 255)-> Alice
    private val root_alice__fully_trusted = EdgeComponent(root, alice, 255, Depth.unconstrained())

    // Root -(60,0)-> Alice
    private val root_alice__marginally_trusted = EdgeComponent(root, alice, 60, Depth.limited(0))

    // Alice -(255,255)-> Root
    private val alice_root = EdgeComponent(alice, root, 255, Depth.unconstrained())

    // Alice -(120, 0)-> Bob
    private val alice_bob = EdgeComponent(alice, bob)

    // Alice -(120, 1)-> Bob
    private val alice_bob_depth_1 = EdgeComponent(alice, bob, 120, Depth.auto(1))

    // Root -> Root
    private val root_root = EdgeComponent(root, root, 120, Depth.limited(1))

    private val root_selfsig = EdgeComponent(root, root, "root@example.org")

    private val bob_selfsig = EdgeComponent(bob, bob, "bob@example.org")

    @Test
    fun `longer path that ends in a selfsig`() {
        val path = Path(root)
        path.append(root_alice__fully_trusted)
        path.append(alice_bob_depth_1)
        path.append(bob_selfsig)

        assertEquals(120, path.amount)
        assertEquals(0, path.residualDepth.value())
    }

    @Test
    fun `verify that an empty Path is properly initialized`() {
        val empty = Path(root)
        assertEquals(root, empty.target)
        assertEquals(listOf(root), empty.certificates)
        assertEquals(1, empty.length)
        assertEquals(120, empty.amount)
        assertTrue { empty.certifications.isEmpty() }
    }

    @Test
    fun `verify that append()ing multiple components properly changes the trust amount of the Path`() {
        val path = Path(root)
        assertEquals(1, path.length)
        assertEquals(120, path.amount) // default amount of an empty path

        path.append(root_alice__fully_trusted)
        assertEquals(listOf(root_alice__fully_trusted), path.certifications)
        assertEquals(listOf(root, alice), path.certificates)
        assertEquals(alice, path.target)
        assertEquals(2, path.length)
        assertEquals(255, path.amount) // single certification -> path has its amount

        path.append(alice_bob)
        assertEquals(listOf(root_alice__fully_trusted, alice_bob), path.certifications)
        assertEquals(listOf(root, alice, bob), path.certificates)
        assertEquals(bob, path.target)
        assertEquals(3, path.length)
        assertEquals(120, path.amount) // second certification has less amount, so amount is capped to its value
    }

    @Test
    fun `verify that append()ing a component whose issuer mismatches the target of the Path fails`() {
        val path = Path(root)
        assertEquals(listOf(root), path.certificates)
        assertEquals(1, path.length)
        assertThrows<IllegalArgumentException> { path.append(alice_bob) }
    }

    @Test
    fun `verify that append()ing a component fails if it exceeds the Path's depth`() {
        val path = Path(root)
        path.append(root_alice__marginally_trusted)
        assertEquals(60, path.amount)

        assertThrows<IllegalArgumentException> {
            path.append(alice_bob)
            // not enough depth
        }
    }

    @Test
    fun `verify that append()ing a component fails of the result would contain cycles`() {
        val path = Path(root)
        path.append(root_alice__fully_trusted)
        assertThrows<IllegalArgumentException> {
            path.append(alice_root)
            // cyclic path
        }
    }

    @Test
    fun `trust root binding its identity is fine`() {
        val path = Path(root)
        path.append(root_selfsig)

        assertEquals(2, path.length)
    }


    @Test
    fun `verify that a Path cannot point to its own root via a delegation`() {
        val path = Path(root)
        assertThrows<IllegalArgumentException> {
            path.append(root_root)
        }
    }
}