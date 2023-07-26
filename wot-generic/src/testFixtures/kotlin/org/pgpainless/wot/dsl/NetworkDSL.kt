// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dsl

import org.pgpainless.wot.network.*
import org.pgpainless.wot.query.Path
import java.util.*

/**
 * Tons of useful DSL for [Network]-related testing.
 */
interface NetworkDSL {

    /**
     * Create [Node] from [String] fingerprint.
     */
    fun Node(fingerprint: String): Node =
            Node(Identifier(fingerprint), null, RevocationState.notRevoked(), mapOf())

    /**
     * Create [Node] from [String] fingerprint and non-revoked [userId].
     */
    fun Node(fingerprint: String, userId: String): Node = Node(
            Identifier(fingerprint), null, RevocationState.notRevoked(), mapOf(userId to RevocationState.notRevoked()))

    fun Node(original: Node, userId: String): Node = Node(
            original.fingerprint, original.expirationTime, original.revocationState, original.userIds.plus(userId to RevocationState.notRevoked())
    )

    /**
     * Create [Edge.Delegation] from two [Node] nodes.
     */
    fun Delegation(issuer: Node, target: Node): Edge.Delegation =
            Delegation(issuer, target, Date())

    fun Delegation(issuer: Node, target: Node, creationTime: Date): Edge.Delegation =
            Edge.Delegation(issuer, target, creationTime, null, false, 120, TrustDepth.limited(0), RegexSet.wildcard())

    /**
     * Create [Edge.Certification] from two [Node] nodes and a target [userId].
     */
    fun Certification(issuer: Node, target: Node, userId: String): Edge.Certification =
            Certification(issuer, target, userId, Date())

    /**
     * Construct a [Edge.Certification] with default values. The result is non-expiring, will be exportable and has a
     * trust amount of 120, a depth of 0 and a wildcard regex.
     *
     * @param issuer synopsis of the certificate that issued the [Edge.Certification]
     * @param target synopsis of the certificate that is target of this [Edge.Certification]
     * @param targetUserId optional user-id. If this is null, the [Edge.Certification] is made over the primary key of the target.
     * @param creationTime creation time of the [Edge.Certification]
     */
    fun Certification(issuer: Node, target: Node, targetUserId: String, creationTime: Date): Edge.Certification =
            Edge.Certification(issuer, target, targetUserId, creationTime, null, true, 120, TrustDepth.limited(0))

    fun Delegation(issuer: Node, target: Node, amount: Int, depth: Int): Edge.Delegation =
            Delegation(issuer, target, amount, TrustDepth.auto(depth))

    fun Delegation(issuer: Node, target: Node, amount: Int, depth: TrustDepth): Edge.Delegation =
            Edge.Delegation(issuer, target, Date(), null, true, amount, depth, RegexSet.wildcard())

    /**
     * Add a single [Node] built from a [String] fingerprint to the builder.
     */
    fun Network.Builder.addNode(fingerprint: String): Network.Builder {
        return addNode(Node(fingerprint))
    }

    /**
     * Add a single [Node] built from a [String] fingerprint and [userId] to the builder.
     */
    fun Network.Builder.addNode(fingerprint: String, userId: String): Network.Builder {
        return addNode(Node(fingerprint, userId))
    }

    /**
     * Add multiple [Node] nodes built from [String] fingerprints to the builder.
     */
    fun Network.Builder.addNodes(vararg fingerprints: String) {
        for (fingerprint in fingerprints) {
            addNode(fingerprint)
        }
    }

    /**
     * Add an edge between the [Node] with fingerprint [issuer] and
     * the [Node] with fingerprint [target].
     * If either the issuer or target node doesn't exist, throw an [IllegalArgumentException].
     */
    fun Network.Builder.addEdge(issuer: String, target: String): Network.Builder {
        val issuerNode = nodes[Identifier(issuer)]!!
        val targetNode = nodes[Identifier(target)]!!
        return addEdge(Delegation(issuerNode, targetNode))
    }

    /**
     * Add an edge for [userId] between the [Node] with fingerprint [issuer] and
     * the [Node] with fingerprint [target].
     * If either the issuer or target node doesn't exist, throw an [IllegalArgumentException].
     */
    fun Network.Builder.addEdge(issuer: String, target: String, userId: String): Network.Builder {
        val issuerNode = nodes[Identifier(issuer)]!!
        val targetNode = nodes[Identifier(target)]!!
        return addEdge(Certification(issuerNode, targetNode, userId))
    }

    /**
     * Add an edge between the issuer and target node. If either of them doesn't exist, add
     * a new node for them to the builder.
     */
    fun Network.Builder.buildEdge(issuer: String, target: String): Network.Builder {
        val issuerNode = nodes.getOrPut(Identifier(issuer)) { Node(issuer) }
        val targetNode = nodes.getOrPut(Identifier(target)) { Node(target) }
        return addEdge(Delegation(issuerNode, targetNode))
    }

    /**
     * Add an edge for [userId] between the issuer and the target node. If either of them doesn't
     * exist, add a new node.
     * If the target node exists, but doesn't carry the [userId], replace it with a copy with
     * the [userId] inserted.
     */
    fun Network.Builder.buildEdge(issuer: String, target: String, userId: String): Network.Builder {
        val issuerNode = nodes.getOrPut(Identifier(issuer)) { Node(issuer)}
        val targetNode = Node(nodes.getOrPut(Identifier(target)) { Node(target, userId) }, userId)
        return addEdge(Certification(issuerNode, targetNode, userId))
    }

    fun Network.Builder.buildEdge(issuer: String, target: String, amount: Int, depth: Int): Network.Builder {
        val issuerNode = nodes.getOrPut(Identifier(issuer)) { Node(issuer) }
        val targetNode = nodes.getOrPut(Identifier(target)) { Node(target) }
        return addEdge(Edge.Delegation(issuerNode, targetNode, Date(), null, true, amount, TrustDepth.auto(depth), RegexSet.wildcard()))
    }

    fun Network.Builder.buildEdge(issuer: String, target: String, amount: Int, depth: Int, regexSet: RegexSet): Network.Builder {
        val issuerNode = nodes.getOrPut(Identifier(issuer)) { Node(issuer) }
        val targetNode = nodes.getOrPut(Identifier(target)) { Node(target) }
        return addEdge(Edge.Delegation(issuerNode, targetNode, Date(), null, true, amount, TrustDepth.auto(depth), regexSet))
    }

    fun Network.getEdgesFor(issuer: Identifier, target: Identifier): Edge? {
        return edges[issuer to target]
    }

    fun Network.getEdgesFor(issuer: String, target: String): Edge? {
        return getEdgesFor(Identifier(issuer), Identifier(target))
    }

    fun Network.getEdgeFor(issuer: Identifier, target: Identifier): List<Edge.Component>? {
        return getEdgeFor(issuer, target, null)
    }

    fun Network.getEdgeFor(issuer: Identifier, target: Identifier, userId: String?): List<Edge.Component> {
        val edge = getEdgesFor(issuer, target) ?: return listOf()
        return if (userId == null) {
            edge.delegations.toList()
        } else {
            edge.certifications[userId]?.toList() ?: listOf()
        }
    }

    fun Network.getEdgeFor(issuer: String, target: String): List<Edge.Component>? {
        return getEdgeFor(issuer, target, null)
    }

    fun Network.getEdgeFor(issuer: String, target: String, userId: String?): List<Edge.Component>? {
        return getEdgeFor(Identifier(issuer), Identifier(target), userId)
    }

    fun Date.plusMillis(millis: Long): Date {
        return Date(time + millis)
    }

    fun Date.plusSeconds(seconds: Long): Date {
        return plusMillis(1000L * seconds)
    }

    fun Date.plusMinutes(minutes: Long): Date {
        return plusSeconds(60 * minutes)
    }

    fun Date.plusHours(hours: Long): Date {
        return plusMinutes(60 * hours)
    }

    fun Date.plusDays(days: Long): Date {
        return plusHours(24 * days)
    }

    fun domainRegex(domain: String): RegexSet {
        return RegexSet.fromExpression("<[^>]+[@.]" + domain.replace(".", "\\.") + ">$")
    }

    /**
     * Lambda with Receiver.
     *
     * @see <a href="https://betterprogramming.pub/test-data-creation-using-the-power-of-kotlin-dsl-9526a1fad05b"/>
     */
    fun buildNetwork(builderAction: Network.Builder.() -> Unit): Network {
        val builder = Network.builder()
        builder.builderAction()
        return builder.build()
    }

    fun Path.assertNodeFingerprints(fingerprints: List<Identifier>): Boolean {
        return root.fingerprint == fingerprints[0] && certificates.withIndex().all { (i, node) ->
            fingerprints[i + 1] == node.fingerprint
        }
    }
}