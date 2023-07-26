// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.wot.network.Edge
import org.pgpainless.wot.network.Identifier
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.testfixtures.TestCertificateStores
import org.pgpainless.wot.testfixtures.WotTestVectors
import kotlin.test.*

class PGPNetworkParserTest {

    private val fooBankCa = fingerprintOf(WotTestVectors.freshFooBankCaCert)
    private val fooBankEmployee = fingerprintOf(WotTestVectors.freshFooBankEmployeeCert)
    private val fooBankAdmin = fingerprintOf(WotTestVectors.freshFooBankAdminCert)
    private val barBankCa = fingerprintOf(WotTestVectors.freshBarBankCaCert)
    private val barBankEmployee = fingerprintOf(WotTestVectors.freshBarBankEmployeeCert)

    private fun fingerprintOf(cert: PGPPublicKeyRing): Identifier {
        return Identifier(OpenPgpFingerprint.of(cert).toString())
    }

    @Test
    fun testWithTwoNodesAndOneDelegation() {
        val certD = TestCertificateStores.oneDelegationGraph()
        val network = PGPNetworkParser(certD).buildNetwork()

        assertEquals(2, network.nodes.size)
        assertHasEdge(network, fooBankAdmin, barBankCa)

        assertHasNoEdge(network, barBankCa, fooBankAdmin)
    }

    @Test
    fun testWithCrossSignedCertificates() {
        val certD = TestCertificateStores.disconnectedGraph()
        val network = PGPNetworkParser(certD).buildNetwork()

        assertEquals(5, network.nodes.size)
        assertTrue {
            listOf(fooBankCa, fooBankEmployee, fooBankAdmin, barBankCa, barBankEmployee).all {
                network.nodes.containsKey(it)
            }
        }

        val fooBankCaEdges = network.getIssuedBy(fooBankCa)!!
        assertEquals(2, fooBankCaEdges.size)

        val fbc2fbe = getEdgeFromTo(network, fooBankCa, fooBankEmployee)
        assertNotNull(fbc2fbe)

        val fbc2fba = getEdgeFromTo(network, fooBankCa, fooBankAdmin)
        assertNotNull(fbc2fba)

        assertHasIssuerAndTarget(fbc2fbe, fooBankCa, fooBankEmployee)
        assertHasIssuerAndTarget(fbc2fba, fooBankCa, fooBankAdmin)

        assertHasEdge(network, barBankCa, barBankEmployee)

        assertHasNoEdge(network, fooBankCa, barBankCa)
    }

    @Test
    fun testWotCreationOfEmptyCertificates() {
        val certD = TestCertificateStores.emptyGraph()
        val network = PGPNetworkParser(certD).buildNetwork()

        assertTrue { network.nodes.isEmpty() }
        assertTrue { network.edges.isEmpty() }
    }

    @Test
    fun testWotWithAnomaly() {
        val store = TestCertificateStores.anomalyGraph()
        val network = PGPNetworkParser(store).buildNetwork()

        assertEquals(1, network.nodes.size)
    }

    private fun assertHasIssuerAndTarget(
            certifications: Edge,
            issuer: Identifier,
            target: Identifier) {
        assertEquals(issuer, certifications.issuer.fingerprint)
        assertEquals(target, certifications.target.fingerprint)
    }

    private fun assertHasEdge(network: Network, issuer: Identifier, target: Identifier) {
        assertNotNull(getEdgeFromTo(network, issuer, target), "Expected edge from $issuer to $target but got none.")
    }

    private fun assertHasNoEdge(network: Network, issuer: Identifier, target: Identifier) {
        val edge = getEdgeFromTo(network, issuer, target)
        assertNull(edge, "Expected no edge from $issuer to $target but got $edge")
    }

    private fun getEdgeFromTo(network: Network, issuer: Identifier, target: Identifier): Edge? {
        return network.edges[issuer to target]
    }

}