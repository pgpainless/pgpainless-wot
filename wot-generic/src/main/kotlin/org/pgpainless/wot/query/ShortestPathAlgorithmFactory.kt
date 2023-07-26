// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.TrustRoot
import java.util.*

/**
 * Factory for instantiating instances of [ShortestPathAlgorithm] implementations.
 */
abstract class ShortestPathAlgorithmFactory {

    /**
     * Instantiate an instance of the [ShortestPathAlgorithm].
     *
     * @param network flow network
     * @param trustRoots set of trust roots
     * @param isCertificationNetwork if true, the network is interpreted as a certification-network,
     * otherwise as an authentication-network.
     * @param referenceTime reference time for certificate validity
     */
    abstract fun createInstance(
            network: Network,
            trustRoots: Set<TrustRoot>,
            isCertificationNetwork: Boolean,
            referenceTime: Date): ShortestPathAlgorithm
}