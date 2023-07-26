// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * Identifier for a node.
 * With OpenPGP, this is a fingerprint.
 */
class Identifier(fingerprint: String) : Comparable<Identifier> {

    val fingerprint: String

    init {
        this.fingerprint = fingerprint.uppercase()
    }

    override fun compareTo(other: Identifier): Int {
        return fingerprint.compareTo(other.fingerprint)
    }

    override fun equals(other: Any?): Boolean {
        return other?.toString() == toString()
    }

    override fun hashCode(): Int {
        return toString().hashCode()
    }

    override fun toString(): String {
        return fingerprint.uppercase()
    }
}