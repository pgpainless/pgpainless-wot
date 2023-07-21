// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.network.*
import org.pgpainless.wot.query.Query

/**
 * Web of Trust API, offering different operations.
 *
 * @param network initialized [Network] containing certificates as nodes and certifications as edges.
 * @param trustRoots one or more [Fingerprints][Fingerprint] of trust-roots.
 * @param gossip if true, consider all certificates as weakly trusted trust-roots
 * @param certificationNetwork if true, all certifications are treated as delegations with infinite trust depth and no regular expressions
 * @param trustAmount minimum trust amount
 * @param referenceTime reference time at which the web of trust is evaluated
 */
class WebOfTrustAPI(
        val network: Network,
        val trustRoots: Roots,
        val gossip: Boolean = false,
        val certificationNetwork: Boolean = false,
        val trustAmount: Int = AuthenticationLevel.Fully.amount,
        val referenceTime: ReferenceTime = ReferenceTime.now()
): AuthenticateAPI, IdentifyAPI, ListAPI, LookupAPI, PathAPI {

    /**
     * Secondary constructor, taking an [AuthenticationLevel] instead of an [Int].
     */
    constructor(network: Network,
                trustRoots: Roots,
                gossip: Boolean = false,
                certificationNetwork: Boolean = false,
                trustAmount: AuthenticationLevel = AuthenticationLevel.Fully,
                referenceTime: ReferenceTime = ReferenceTime.now()):
            this(network,trustRoots, gossip,certificationNetwork, trustAmount.amount, referenceTime)

    override fun authenticate(fingerprint: Fingerprint, userId: String, email: Boolean): AuthenticateAPI.Result {
        val query = Query(network, trustRoots, certificationNetwork)
        val paths = query.authenticate(fingerprint, userId, trustAmount)
        return AuthenticateAPI.Result(Binding(fingerprint, userId, paths), trustAmount)
    }

    override fun identify(fingerprint: Fingerprint): IdentifyAPI.Result {
        val cert = network.nodes[fingerprint]
                ?: return IdentifyAPI.Result(listOf(), trustAmount)

        val bindings = mutableListOf<Binding>()
        cert.userIds.keys.toList().forEach {
            val query = Query(network, trustRoots, certificationNetwork)
            val paths = query.authenticate(fingerprint, it, trustAmount)
            if (paths.amount != 0) {
                bindings.add(Binding(fingerprint, it, paths))
            }
        }
        return IdentifyAPI.Result(bindings, trustAmount)
    }

    override fun list(): ListAPI.Result {
        val bindings = mutableListOf<Binding>()
        network.nodes.forEach {
            bindings.addAll(identify(it.key).bindings)
        }
        return ListAPI.Result(bindings, trustAmount)
    }

    override fun lookup(userId: String, email: Boolean): LookupAPI.Result {
        val candidates = network.nodes.values.mapNotNull { node ->
            val matches = node.mapToMatchingUserIds(userId, email)
            if (matches.isEmpty()) {
                null
            } else {
                node to matches
            }
        }

        val results = mutableListOf<Binding>()
        candidates.forEach {
            val node = it.first
            val userIds = it.second

            for (mUserId in userIds) {
                authenticate(node.fingerprint, mUserId, email).let { result ->
                    if (result.binding.paths.paths.isNotEmpty()) {
                        results.add(result.binding)
                    }
                }
            }
        }

        return LookupAPI.Result(results, trustAmount)
    }

    override fun path(rootFingerprint: Fingerprint, pathFingerprints: List<Fingerprint>, userId: String): PathAPI.Result {
        TODO("Not yet implemented")
    }

    private fun Node.mapToMatchingUserIds(userId: String, email: Boolean): List<String> {
        val list = mutableListOf<String>()
        userIds.forEach { entry ->
            if (email) {
                if (entry.key.contains("<$userId>")) {
                    list.add(entry.key)
                }
            } else {
                if (entry.key == userId) {
                    list.add(entry.key)
                }
            }
        }
        return list
    }

}