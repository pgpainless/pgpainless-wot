// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.pgpainless.wot.network.Edge
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.network.TrustDepth
import kotlin.math.min

/**
 * A [Path] comprises a root [Node], a list of edges ([Edge.Components][Edge.Component]), as well as a
 * residual depth.
 *
 * @param root root of the path
 * @param edges list of edges from the root to the target
 * @param residualDepth residual depth that is decreased each time another edge is appended
 */
class Path(
        val root: Node,
        private val edges: MutableList<Edge.Component>,
        var residualDepth: TrustDepth
) {

    /**
     * Construct a [Path] only consisting of the trust root.
     * The [Path] will have an empty list of edges and an unconstrained residual [TrustDepth].
     *
     * @param root trust root
     */
    constructor(root: Node) : this(
            root, mutableListOf<Edge.Component>(), TrustDepth.unlimited())

    /**
     * Current target of the path.
     * This corresponds to the target of the last entry in the edge list.
     */
    val target: Node
        get() {
            return if (edges.isEmpty()) {
                root
            } else {
                edges.last().target
            }
        }

    /**
     * List of [Nodes][Node] (nodes) of the path.
     * The first entry is the [root]. The other entries are the targets of the edges.
     */
    val certificates: List<Node>
        get() {
            val certs: MutableList<Node> = mutableListOf(root)
            for (certification in edges) {
                certs.add(certification.target)
            }
            return certs
        }

    /**
     * The length of the path, counted in nodes.
     * A path with a single edge between node A and B has length 2, the empty path with only a trust root has length 1.
     */
    val length: Int
        get() = edges.size + 1

    /**
     * List of edges.
     */
    val certifications: List<Edge.Component>
        get() = edges.toList()

    /**
     * Trust amount of the path.
     * This corresponds to the smallest trust amount of any edge in the path.
     */
    val amount: Int
        get() = if (edges.isEmpty()) {
            120
        } else {
            var min = 255
            for (edge in edges) {
                min = min(min, edge.trustAmount)
            }
            min
        }

    fun append(nComponent: Edge.Component) {
        append(nComponent, false)
    }

    /**
     * Append an edge to the path and decrease the [residualDepth] of the path by 1.
     *
     * @throws IllegalArgumentException if the target at the end of the path is not equal to the issuer of the edge.
     * @throws IllegalArgumentException if the path runs out of residual depth
     * @throws IllegalArgumentException if the addition of the [Edge.Component] would result in a cyclic path
     */
    fun append(nComponent: Edge.Component, certificationNetwork: Boolean) {
        require(target.fingerprint == nComponent.issuer.fingerprint) {
            "Cannot append edge to path: Path's tail is not issuer of the edge."
        }
        require(certificationNetwork || residualDepth > 0) {
            "Not enough depth."
        }

        var cyclic = false

        // An edge that points to the root is only allowed as the first and last edge
        if ((edges.size > 0) && (root.fingerprint == nComponent.target.fingerprint)) {
            cyclic = true
        }
        // And it's only legal if the edge points to the target User ID
        // (XX: Do we know the target User ID here? Currently, we only check for != null)
        if ((edges.size == 0) && (root.fingerprint == nComponent.target.fingerprint) && (nComponent is Edge.Delegation)) {
            cyclic = true
        }

        for ((i, component) in edges.withIndex()) {
            if (cyclic) {
                break
            }
            // existing edge points to c's target -> illegal cycle
            if (nComponent.target.fingerprint == component.target.fingerprint) {
                cyclic = if (edges.lastIndex != i) {
                    // Cycle in the middle of the ~~street~~ path
                    true
                } else {
                    // Not a cycle, if we point to a different user-id
                    nComponent is Edge.Certification && component is Edge.Certification &&
                            nComponent.userId == component.userId
                }
            }
        }
        require(!cyclic) { "Adding the edge to the path would create a cycle." }

        if (!certificationNetwork)
            residualDepth = nComponent.trustDepth.min(residualDepth.reduce(1))
        edges.add(nComponent)
    }

    override fun toString(): String {
        return "{${root.fingerprint}} => {${edges.map { it.target }.joinToString(" -> ")}} (residual {$residualDepth})"
    }
}