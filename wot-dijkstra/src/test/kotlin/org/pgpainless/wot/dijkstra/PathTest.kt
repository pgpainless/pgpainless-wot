package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.dijkstra.sq.*
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PathTest {

    private val root = CertSynopsis(
            Fingerprint("aabbccddeeAABBCCDDEEaabbccddeeAABBCCDDEE"),
            null,
            RevocationState.notRevoked(),
            mapOf())
    private val alice = CertSynopsis(
            Fingerprint("0000000000000000000000000000000000000000"),
            null,
            RevocationState.notRevoked(),
            mapOf())
    private val bob = CertSynopsis(
            Fingerprint("1111111111111111111111111111111111111111"),
            null,
            RevocationState.notRevoked(),
            mapOf())

    // Root -(255, 255)-> Alice
    private val root_alice__fully_trusted = Certification(root, alice, 255, Depth.unconstrained())
    // Root -(60,0)-> Alice
    private val root_alice__marginally_trusted = Certification(root, alice, 60, Depth.limited(0))
    // Alice -(255,255)-> Root
    private val alice_root = Certification(alice, root, 255, Depth.unconstrained())
    // Alice -(120, 1)-> Bob
    private val alice_bob = Certification(alice, null, bob, Date())
    // Root -> Root
    private val root_root = Certification(root, root, 120, Depth.limited(1))

    @Test
    fun emptyPathTest() {
        val empty = Path(root)
        assertEquals(root, empty.target)
        assertEquals(listOf(root), empty.certificates)
        assertEquals(1, empty.length)
        assertEquals(120, empty.amount)
        assertTrue { empty.certifications.isEmpty() }
    }

    @Test
    fun appendTest() {
        val path = Path(root)
        assertEquals(listOf(root), path.certificates)

        assertThrows<IllegalArgumentException> { path.append(alice_bob) }
        assertEquals(listOf(root), path.certificates)
        assertEquals(1, path.length)

        path.append(root_alice__fully_trusted)
        assertEquals(listOf(root_alice__fully_trusted), path.certifications)
        assertEquals(listOf(root, alice), path.certificates)
        assertEquals(alice, path.target)
        assertEquals(2, path.length)
        assertEquals(255, path.amount)

        path.append(alice_bob)
        assertEquals(listOf(root_alice__fully_trusted, alice_bob), path.certifications)
        assertEquals(listOf(root, alice, bob), path.certificates)
        assertEquals(bob, path.target)
        assertEquals(3, path.length)
        assertEquals(120, path.amount)
    }

    @Test
    fun appendTest2() {
        val path = Path(root)
        path.append(root_alice__marginally_trusted)
        assertEquals(60, path.amount)

        assertThrows<IllegalArgumentException> {
            path.append(alice_bob)
            // not enough depth
        }
    }

    @Test
    fun appendTest3() {
        val path = Path(root)
        path.append(root_alice__fully_trusted)
        assertThrows<IllegalArgumentException> {
            path.append(alice_root)
            // cyclic path
        }
    }

    @Test
    fun appendTest4() {
        val path = Path(root)
        assertThrows<IllegalArgumentException> { path.append(root_root) }
    }

    fun Certification(issuer: CertSynopsis, target: CertSynopsis, amount: Int, depth: Depth): Certification =
            Certification(issuer, target, null, Date(), null, true, amount, depth, RegexSet.wildcard())
}