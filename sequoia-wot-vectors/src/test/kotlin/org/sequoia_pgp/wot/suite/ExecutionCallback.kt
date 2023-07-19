// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite

import org.sequoia_pgp.wot.vectors.ArtifactVectors

interface ExecutionCallback {
    fun execute(vectors: ArtifactVectors, arguments: Array<String>): Pair<String, Int>
}