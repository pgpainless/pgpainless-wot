// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.pgpainless.wot.network.Identifier

/**
 * Query algorithm for searching paths inside a flow network.
 */
interface ShortestPathAlgorithm {

    /**
     * Search for paths to the target node and user-id, aiming for a given minimal trust amount.
     */
    fun search(targetFpr: Identifier, targetUserid: String, targetTrustAmount: Int): Paths
}