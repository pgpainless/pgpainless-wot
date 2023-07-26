// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

class Network(
        val nodes: Map<Identifier, Node>,
        val edges: Map<Pair<Identifier, Identifier>, Edge>) {

    constructor(): this(mapOf(), mapOf())

    fun getIssuedBy(identifier: Identifier): List<Edge> {
        return edges.filter { it.key.first == identifier }.map { it.value }
    }

    fun getIssuedFor(identifier: Identifier): List<Edge> {
        return edges.filter { it.key.second == identifier }.map { it.value }
    }

    val numberOfEdges: Int
        get() = edges.size

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