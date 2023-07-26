// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import java.util.*

/**
 * Edge between two nodes.
 * The edge is made up of at least one delegation or certification, but can contain multiple components.
 */
class Edge(val issuer: Node,
           val target: Node,
           val delegations: MutableSet<Delegation>,
           val certifications: MutableMap<String, MutableSet<Certification>>) {

    constructor(issuer: Node, target: Node):
            this(issuer, target, mutableSetOf(), mutableMapOf())

    constructor(component: Component):
        this(component.issuer, component.target,
                buildSet<Delegation> {
                    if (component is Delegation) add(component)
                }.toMutableSet(),
                buildMap<String, MutableSet<Certification>> {
                    if (component is Certification) put(component.userId, mutableSetOf(component))
                }.toMutableMap())

    /**
     * Join this edge with another one.
     */
    fun join(other: Edge): Edge {
        require(issuer.fingerprint == other.issuer.fingerprint)
        require(target.fingerprint == other.target.fingerprint)

        if (other === this) {
            return this
        }

        return this.apply {
            other.delegations.forEach {
                addComponent(it)
            }
            other.certifications.forEach { e ->
                e.value.forEach { addComponent(it) }
            }
        }
    }

    /**
     * Add a singe component to the edge.
     */
    fun addComponent(component: Component) {
        require(issuer.fingerprint == component.issuer.fingerprint)
        require(target.fingerprint == component.target.fingerprint)

        if (component is Certification) {
            val forUserId = certifications.getOrPut(component.userId) { mutableSetOf() }
            if (forUserId.isEmpty()) {
                forUserId.add(component)
                return
            }
            val existing = forUserId.first()
            if (existing.creationTime < component.creationTime) {
                forUserId.clear()
            }
            if (component.creationTime >= existing.creationTime) {
                forUserId.add(component)
            }
        } else {
            if (delegations.isEmpty()) {
                delegations.add(component as Delegation)
                return
            }
            val existing = delegations.first()
            if (existing.creationTime < component.creationTime) {
                delegations.clear()
            }
            if (component.creationTime >= existing.creationTime) {
                delegations.add(component as Delegation)
            }
        }
    }

    /**
     * Return a joined map of all components of this edge. Certifications are keyed by userId, while delegations
     * are keyed with null.
     */
    fun components(): Map<String?, List<Component>> {
        return mutableMapOf<String?, List<Component>>()
                .apply {
                    certifications.forEach { (uid, certs) ->
                        put(uid, certs.map { it })
                    }
                    if (delegations.isNotEmpty()) {
                        put(null, delegations.map { it })
                    }
                }
    }

    override fun toString(): String {
        return buildString {
            components().values.flatten().forEach {
                appendLine(it.toString())
            }
        }
    }

    abstract class Component(
            val issuer: Node,
            val target: Node,
            val creationTime: Date,
            val expirationTime: Date?,
            val exportable: Boolean,
            val trustAmount: Int,
            val trustDepth: TrustDepth,
            val regexes: RegexSet) {

    }

    /**
     * Delegation made as a direct-key signature.
     */
    class Delegation(
            issuer: Node,
            target: Node,
            creationTime: Date,
            expirationTime: Date?,
            exportable: Boolean,
            trustAmount: Int,
            trustDepth: TrustDepth,
            regexes: RegexSet):
            Component(issuer, target, creationTime, expirationTime, exportable, trustAmount, trustDepth, regexes) {

        override fun toString(): String {
            return "${issuer.fingerprint} certifies binding: null <-> ${target.fingerprint} [${trustAmount}]"
        }
    }

    /**
     * Certification made over a user-id.
     */
    class Certification(issuer: Node,
                        target: Node,
                        val userId: String,
                        creationTime: Date,
                        expirationTime: Date?,
                        exportable: Boolean,
                        trustAmount: Int?,
                        trustDepth: TrustDepth?,
                        regexes: RegexSet? = RegexSet.wildcard()):
            Component(issuer, target, creationTime, expirationTime, exportable, trustAmount?: 120, trustDepth?: TrustDepth.limited(0), regexes ?: RegexSet.wildcard()) {

        override fun toString(): String {
            return "${issuer.fingerprint} certifies binding: $userId <-> ${target.fingerprint} [${trustAmount}]"
        }
    }
}