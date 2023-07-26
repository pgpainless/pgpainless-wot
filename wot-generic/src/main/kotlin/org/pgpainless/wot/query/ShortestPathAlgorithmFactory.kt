// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.TrustRoot
import java.util.*

abstract class ShortestPathAlgorithmFactory {

    abstract fun createInstance(
            network: Network,
            trustRoots: Set<TrustRoot>,
            isCertificationNetwork: Boolean,
            referenceTime: Date): ShortestPathAlgorithm
}