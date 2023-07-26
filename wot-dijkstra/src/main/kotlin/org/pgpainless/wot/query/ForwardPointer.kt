// SPDX-FileCopyrightText: 2023 Heiko Schäfer <heiko@schaefer.name>, 2022-2023, pep foundation
//
// SPDX-License-Identifier: LGPL-2.0-only

package org.pgpainless.wot.query

import org.pgpainless.wot.network.Edge


/**
 * Pointer type for Dijsktra's algorithm.
 * This encapsulates the outgoing edge (there may be multiple edges between a source and a target node).
 */
internal data class ForwardPointer(
        // If null, then the node is itself the target.
        val next: Edge.Component?
)