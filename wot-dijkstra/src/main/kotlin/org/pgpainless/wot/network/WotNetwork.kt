// SPDX-FileCopyrightText: 2023 Heiko Schäfer <heiko@schaefer.name>
//
// SPDX-License-Identifier: LGPL-2.0-only

package org.pgpainless.wot.network

import org.pgpainless.wot.query.Path
import java.util.*
import kotlin.collections.HashMap

/**
 * A wrapper for `Network` that performs the following functions:
 *
 * - Expose an (experimental) API that simplifies the implementation of the WoT algorithm (in `Query`)
 *   - TODO: polish, and possibly upstream into `Network`
 *
 * - Form residual networks for the Ford-Fulkerson algorithm via `suppressPath()`
 *   - `getEffectiveTrustAmount()` returns effective trust amounts of certifications
 *     (taking the residual network into account)
 */
internal class WotNetwork(
        private val network: Network,
        private val certificationNetwork: Boolean,
        private val referenceTime: Date) {

    fun nodeByFpr(fpr: Identifier): Node? = network.nodes[fpr]

    fun getSelfSig(targetFpr: Identifier, targetUserid: String): Edge.Component? {
        val target = nodeByFpr(targetFpr)

        if (target?.userIds?.get(targetUserid) != null) {
            // Return a synthesized self-binding.
            // XX: This EC should be generated during network generation.
            return Edge.Certification(target, target, targetUserid, referenceTime,
                    null, true, 120, TrustDepth.limited(0))
        } else
            return null
    }

    /**
     * Return list of Edge.Components that point to `fpr`.
     *
     * Doesn't currently return self-bindings.
     *
     * `targetUserid` is currently only evaluated to check matching with regex scoped delegations.
     * Doesn't currently filter out Edge.Components that point to `fpr`, but a different User ID
     * (FIXME: filter by target User ID, if fpr == target, and target user id != null, then simplify Query?)
     *
     * In authentication network mode:
     * - only return Edge.Components whose depth allows authentication of a path that is `curLen` long.
     * - only return Edge.Components whose regexes match `targetUserid`.
     */
    fun certificationsForSignee(fpr: Identifier, targetUserid: String, curLen: Int): List<Edge.Component> {
        val edges = network.edges.filter { it.key.second == fpr }.map { it.value }

        val ec = edges.map { edge ->
            edge.components().map { it.value }.flatten()
        }
                .flatten()
                .filter {
                    if (!certificationNetwork) {
                        // Authentication network mode: honor depth limitation and regexes
                        it.trustDepth >= curLen && it.regexes.matches(targetUserid)
                    } else {
                        // Certification network mode: Keep certifications of any depth, and ignore regex scoping
                        true
                    }
                }

    return ec
}

fun isValidTarget(targetFpr: Identifier, targetUserid: String): Node? {

    // Node must be in the network.
    val target = nodeByFpr(targetFpr) ?: return null

    // Target may not be expired at the reference time.
    if ((target.expirationTime != null) &&
            (target.expirationTime!! <= referenceTime)) {
        return null
    }

    // Target may not be revoked at the reference time.
    if (target.revocationState.isEffective(referenceTime)) {
        return null
    }

    // The target doesn't need to have self-signed the User ID to authenticate the User ID.
    // But if the target has revoked it, then it can't be authenticated.
    val targetUa: RevocationState? = target.userIds[targetUserid]
    if (targetUa != null && targetUa.isEffective(referenceTime)) {
        return null
    }

    return target
}


// Modifiers are processed in order by getEffectiveTrustAmount() [first cap, then suppress]
private val capCertificate: HashMap<Identifier, Int> = HashMap()
private val suppressPath: HashMap<Pair<Identifier, Identifier>, Int> = HashMap()

/**
 * Get effective trust amount for a certification:
 * Cap if the root has limited trust, and take into account additional constraints of the residual network.
 */
fun getEffectiveTrustAmount(ec: Edge.Component): Int {
    // Start from trust amount on the certification
    var amount = ec.trustAmount

    // Cap to issuer's `capCertificate`, if set.
    // (Used in case of less than fully trusted roots)
    capCertificate[ec.issuer.fingerprint]?.let {
        if (it < amount) {
            amount = it
        }
    }

    // Suppress by certificate (for Ford-Fulkerson residual network)
    suppressPath[Pair(ec.issuer.fingerprint, ec.target.fingerprint)]?.let {
        if (amount > it) {
            amount -= it
        } else {
            amount = 0
        }
    }

    return amount
}

/** Limit a certificate's initial trust amount to `amount` */
fun capCertificate(fingerprint: Identifier, amount: Int) {
    capCertificate[fingerprint] = amount
}

/**
 * Add suppression rules for all certifications along the specified path:
 * Each edge is suppressed by `amountToSuppress`.
 */
fun suppressPath(path: Path, amountToSuppress: Int) {
    if (amountToSuppress == 0) return
    assert(amountToSuppress <= 120)

    for (c in path.certifications) {
        val curAmount = suppressPath[Pair(c.issuer.fingerprint, c.target.fingerprint)] ?: 0
        val newAmount = curAmount + amountToSuppress
        assert(newAmount <= 120)

        suppressPath[Pair(c.issuer.fingerprint, c.target.fingerprint)] = newAmount
    }
}
}