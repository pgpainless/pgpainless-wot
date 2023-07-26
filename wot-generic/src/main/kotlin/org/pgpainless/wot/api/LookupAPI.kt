// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

interface LookupAPI {

    fun lookup(userId: String, email: Boolean = false): Result

    data class Result(val bindings: List<Binding>, val targetAmount: Int) {
        val acceptable: Boolean
            get() = bindings.any {
                it.paths.amount >= targetAmount
            }
    }
}
