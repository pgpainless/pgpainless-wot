// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.network.Fingerprint

/**
 * Authenticate a binding.
 * A binding is a pair consisting of a certificate and a User ID.
 */
interface AuthenticateAPI {

    /**
     * Authenticate the binding between a fingerprint and a given userId.
     *
     * @param arguments arguments
     */
    fun authenticate(fingerprint: Fingerprint, userId: String, email: Boolean = false): Result

    /**
     * Authentication result.
     * @param targetAmount the targeted trust amount required to achieve full authentication
     * @param paths the number of paths
     */
    data class Result(val binding: Binding, val targetAmount: Int) {
        val percentage: Int
            get() = binding.percentage(targetAmount)

        val acceptable: Boolean
            get() = binding.paths.amount >= targetAmount
    }

}
