// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * Flow-Network containing nodes and edges between them.
 *
 * @param nodes map of nodes keyed by their identifier
 * @param edges map of issuer/target pairs to edges
 */
class Network(
        val nodes: Map<Identifier, Node>,
        val edges: Map<Pair<Identifier, Identifier>, Edge>) {

    constructor(): this(mapOf(), mapOf())

    /**
     * Return all edges issued by the node with the given identifier.
     *
     * @param issuer identifier of the issuer node
     */
    fun getIssuedBy(issuer: Identifier): List<Edge> {
        return edges.filter { it.key.first == issuer }.map { it.value }
    }

    /**
     * Return all edges issued over the node with the given identifier.
     *
     * @param target identifier of the target node
     */
    fun getIssuedFor(target: Identifier): List<Edge> {
        return edges.filter { it.key.second == target }.map { it.value }
    }

    /**
     * The total number of edges in the network.
     */
    val numberOfEdges: Int
        get() = edges.size

    /**
     * The total number of edge-components (signatures) that make up the network.
     */
    val numberOfSignatures: Int
        get() = edges.values.sumOf { edge ->
            edge.components().values.sumOf { it.size }
        }

    override fun toString(): String {
        return buildString {
            appendLine("Network with ${nodes.size} nodes, $numberOfEdges edges:")
            for(component in edges.values) append(component)
        }
    }

    companion object {

        /**
         * Return a [Builder] for the Network.
         */
        @JvmStatic
        fun builder(): Builder = Builder()
    }

    class Builder internal constructor() {
        val nodes: MutableMap<Identifier, Node> = mutableMapOf()
        private val protoEdges: MutableMap<Pair<Identifier, Identifier>, Edge> = mutableMapOf()

        fun addNode(node: Node): Builder {
            nodes[node.fingerprint] = node
            return this
        }

        fun addEdge(edge: Edge.Component): Builder {
            protoEdges.getOrPut(Pair(edge.issuer.fingerprint, edge.target.fingerprint)) {
                Edge(edge.issuer, edge.target)
            }.addComponent(edge)
            return this
        }

        fun build(): Network {
            return Network(nodes, protoEdges)
        }
    }
}