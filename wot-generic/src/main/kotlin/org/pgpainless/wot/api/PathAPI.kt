// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.network.Identifier

interface PathAPI {

    fun path(rootFingerprint: Identifier, pathFingerprints: List<Identifier>, userId: String): Result

    interface Result {

        fun isSuccess(): Boolean

        class Success: Result {
            override fun isSuccess(): Boolean {
                return true
            }
        }

        data class Failure(val information: List<String>): Result {
            override fun isSuccess(): Boolean {
                return false
            }
        }
    }
}
