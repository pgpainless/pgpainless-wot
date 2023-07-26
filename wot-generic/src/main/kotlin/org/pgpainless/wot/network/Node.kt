// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import java.util.*

/**
 * A node in the network.
 */
class Node(val fingerprint: Identifier,
           val expirationTime: Date? = null,
           val revocationState: RevocationState = RevocationState.notRevoked(),
           val userIds : Map<String, RevocationState> = mapOf()) {

    override fun toString(): String {
        return buildString {
            append(fingerprint)
            if (userIds.isNotEmpty()) {
                append(" (${userIds.keys.first()})")
            }
        }
    }
}