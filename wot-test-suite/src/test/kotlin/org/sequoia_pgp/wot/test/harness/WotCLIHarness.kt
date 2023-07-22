// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.test.harness

import org.pgpainless.wot.cli.WebOfTrustCLI
import org.sequoia_pgp.wot.test.ExecutionCallback
import org.sequoia_pgp.wot.vectors.ArtifactVectors
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * Harness for the [WebOfTrustCLI] class.
 */
class WotCLIHarness: Harness() {

    override fun runner(): ExecutionCallback {
        return object: ExecutionCallback {

            override fun execute(vectors: ArtifactVectors, arguments: Array<String>): Pair<String, Int> {
                val origStdout = System.out
                val origStderr = System.err

                val bOut = ByteArrayOutputStream()
                System.setOut(PrintStream(bOut))
                System.setErr(PrintStream(bOut))

                val exitCode = WebOfTrustCLI.execute(arguments)

                System.setOut(origStdout)
                System.setErr(origStderr)
                return bOut.toString() to exitCode
            }

        }
    }
}