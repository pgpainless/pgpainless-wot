// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import java.util.regex.Pattern

/**
 * Set of regular expressions.
 */
data class RegexSet(val regexStrings: Set<String>) {

    companion object {

        /**
         * Create a [RegexSet] from the given [List] of RegEx strings.
         */
        @JvmStatic
        fun fromExpressions(regexList: List<String>): RegexSet {
            return RegexSet(regexList.toSet())
        }

        /**
         * Create a [RegexSet] from a single RegEx string.
         */
        @JvmStatic
        fun fromExpression(regex: String): RegexSet {
            return fromExpressions(listOf(regex))
        }

        /**
         * Create a wildcard RegEx (empty list of RegEx strings).
         */
        @JvmStatic
        fun wildcard(): RegexSet {
            return fromExpressions(listOf())
        }
    }

    /**
     * Return true if the given [string] matches the [RegexSet].
     * That is if at least one RegEx in the set matches the [string], or if the set represents a wildcard.
     */
    fun matches(string: String): Boolean {
        // wildcard or any match
        return regexStrings.isEmpty() || regexStrings.any {
            Pattern.compile(it).matcher(string).find()
        }
    }

    override fun toString(): String {
        return regexStrings.joinToString(", ")
    }
}