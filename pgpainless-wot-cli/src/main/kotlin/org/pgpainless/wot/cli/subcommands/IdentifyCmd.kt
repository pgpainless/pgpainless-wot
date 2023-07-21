// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.cli.WebOfTrustCLI
import org.pgpainless.wot.cli.converters.FingerprintConverter
import org.pgpainless.wot.network.Fingerprint
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import java.util.concurrent.Callable

@Command(name = "identify")
class IdentifyCmd: Callable<Int> {

    @CommandLine.ParentCommand
    lateinit var parent: WebOfTrustCLI

    @Parameters(index = "0", description = ["Certificate fingerprint."], converter = [FingerprintConverter::class])
    lateinit var fingerprint: Fingerprint

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        val result = parent.api.identify(fingerprint)

        print(parent.outputFormatter.format(result))
        return if (result.acceptable) 0 else 1
    }
}