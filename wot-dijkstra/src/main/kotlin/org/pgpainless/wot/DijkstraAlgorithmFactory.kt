// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: LGPL-2.0-only

package org.pgpainless.wot

import java.util.*
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.TrustRoot
import org.pgpainless.wot.query.Dijkstra
import org.pgpainless.wot.query.ShortestPathAlgorithmFactory

class DijkstraAlgorithmFactory : ShortestPathAlgorithmFactory() {

    override fun createInstance(
        network: Network,
        trustRoots: Set<TrustRoot>,
        isCertificationNetwork: Boolean,
        referenceTime: Date
    ): Dijkstra {
        return Dijkstra(network, trustRoots, isCertificationNetwork, referenceTime)
    }
}
