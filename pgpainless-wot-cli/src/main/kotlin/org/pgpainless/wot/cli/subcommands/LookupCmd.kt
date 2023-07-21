// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.cli.WebOfTrustCLI
import picocli.CommandLine.*
import java.util.concurrent.Callable

@Command(name = "lookup")
class LookupCmd: Callable<Int> {

    @ParentCommand
    lateinit var parent: WebOfTrustCLI

    @Option(names = ["--email"], description = ["Consider all user-IDs that contain the given email address."])
    var email = false

    @Parameters(index = "0", description = ["User-ID"])
    lateinit var userId: String

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        val result = parent.api.lookup(userId, email)

        print(parent.outputFormatter.format(result))
        return if (result.acceptable) 0 else 1
    }
}