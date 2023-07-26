// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.pgpainless.wot.network.Identifier

interface ShortestPathAlgorithm {

    fun search(targetFpr: Identifier, targetUserid: String, targetTrustAmount: Int): Paths
}