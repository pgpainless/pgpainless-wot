// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli

import org.pgpainless.PGPainless
import org.pgpainless.certificate_store.PGPainlessCertD
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.PGPNetworkParser
import org.pgpainless.wot.api.WebOfTrustAPI
import org.pgpainless.wot.cli.converters.ReferenceTimeConverter
import org.pgpainless.wot.cli.converters.RootConverter
import org.pgpainless.wot.cli.format.Formatter
import org.pgpainless.wot.cli.format.SQWOTFormatter
import org.pgpainless.wot.cli.subcommands.*
import org.pgpainless.wot.letIf
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.ReferenceTime
import org.pgpainless.wot.network.Root
import org.pgpainless.wot.network.Roots
import pgp.cert_d.BaseDirectoryProvider
import pgp.cert_d.PGPCertificateStoreAdapter
import pgp.cert_d.SpecialNames
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookupFactory
import pgp.certificate_store.PGPCertificateStore
import picocli.CommandLine
import picocli.CommandLine.*
import java.io.File
import java.util.concurrent.Callable
import kotlin.system.exitProcess

/**
 * Command Line Interface for pgpainless-wot, modelled after the reference implementation "sq-wot".
 *
 * @see <a href="https://gitlab.com/sequoia-pgp/sequoia-wot/">Sequoia Web of Trust Reference Implementation</a>
 */
@Command(name = "pgpainless-wot",
    subcommands = [
        AuthenticateCmd::class,
        IdentifyCmd::class,
        ListCmd::class,
        LookupCmd::class,
        PathCmd::class,
        HelpCommand::class
    ]
)
class WotCLI: Callable<Int> {

    @Option(names = ["--trust-root", "-r"], converter = [RootConverter::class])
    var optTrustRoot: List<Root> = listOf()

    @ArgGroup(exclusive = true)
    var optTrustAmount: TrustAmount = TrustAmount()

    @ArgGroup(exclusive = true, multiplicity = "1")
    lateinit var optKeyRing: CertificateSource

    /*
    @Option(names = ["--network"], description = ["Look for missing certificates on a key server or the WKD."])
    var network: Boolean = false

    @Option(names = ["--keyserver"], description=["Change the default keyserver"])
    var keyServer: String = "hkps://keyserver.ubuntu.com"
    */

    @Option(names = ["--gpg-ownertrust"])
    var optGpgOwnerTrust = false

    @Option(names = ["--certification-network"], description = ["Treat the web of trust as a certification network instead of an authentication network."])
    var optCertificationNetwork = false

    @Option(names = ["--gossip"], description = ["Find arbitrary paths by treating all certificates as trust-roots with zero trust."])
    var optGossip = false

    @Option(names = ["--time"], description = ["Reference time."],
        converter = [ReferenceTimeConverter::class])
    val optReferenceTime: ReferenceTime = ReferenceTime.now()

    @Option(names = ["--known-notation"], description = ["Add a notation to the list of known notations."])
    var optKnownNotations: Array<String> = arrayOf()

    class TrustAmount {
        @Option(names = ["--trust-amount", "-a"], description = ["The required amount of trust."])
        var optAmount: Int? = null

        @Option(names = ["--partial"])
        var optPartial: Boolean = false

        @Option(names = ["--full"])
        var optFull: Boolean = false

        @Option(names = ["--double"])
        var optDouble: Boolean = false

        fun get(certificationNetwork: Boolean): Int {
            return when {
                optAmount != null -> optAmount!! // --amount=XY
                optPartial -> 40                           // --partial
                optFull -> 120                             // --full
                optDouble -> 240                           // --double
                else -> if (certificationNetwork) 1200 else 120      // default 120, if --certification-network -> 1200
            }
        }
    }

    class CertificateSource {
        @Option(names = ["--keyring", "-k"], description = ["Specify a keyring file."], required = true)
        var optKeyring: Array<File>? = null

        @Option(names = ["--cert-d"], description = ["Specify a pgp-cert-d base directory."], arity = "0..1",
            fallbackValue = "")
        var optPgpCertD: String? = null

        @Option(names = ["--gpg"], description = ["Read trust roots and keyring from GnuPG."])
        var optGpg = false

        val get: PGPCertificateStore
            get() {
                if (optGpg) {
                    return gpgHelper.readGpgKeyRing()
                }
                if (optKeyring != null) {
                    return KeyRingCertificateStore(
                        optKeyring!!.map {
                            PGPainless.readKeyRing().publicKeyRingCollection(it.inputStream())
                        }
                    )
                }

                if (optPgpCertD == "") {
                    val certDFile = BaseDirectoryProvider.getDefaultBaseDir()
                    val certD = PGPainlessCertD.fileBased(
                        certDFile,
                        InMemorySubkeyLookupFactory())
                    return PGPCertificateStoreAdapter(certD)
                }
                val certD = PGPainlessCertD.fileBased(
                    File(optPgpCertD!!),
                    InMemorySubkeyLookupFactory())
                return PGPCertificateStoreAdapter(certD)
            }
    }

    val outputFormatter: Formatter = SQWOTFormatter()

    private val trustRoots: Roots
        get() {
            return optTrustRoot
                .letIf(optKeyRing.optGpg || optGpgOwnerTrust) {
                    plus(gpgHelper.readGpgOwnertrust())
                }.letIf(optKeyRing.optPgpCertD != null) {
                    try {
                        val rootCert = optKeyRing.get.getCertificate(SpecialNames.TRUST_ROOT)
                        plus(Root(Fingerprint(rootCert.fingerprint), Int.MAX_VALUE))
                    } catch (e: NoSuchElementException) { this }
                }.let { Roots(it) }
        }

    val api: WebOfTrustAPI
        get() {
            val network = PGPNetworkParser(optKeyRing.get)
                .buildNetwork(referenceTime = optReferenceTime)
            return WebOfTrustAPI(
                network = network,
                trustRoots = trustRoots,
                gossip = optGossip,
                certificationNetwork = optCertificationNetwork,
                trustAmount = optTrustAmount.get(optCertificationNetwork),
                referenceTime = optReferenceTime)
        }

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        require(optTrustRoot.isNotEmpty()) {
            "Expected at least one trust-root."
        }

        for (notation in optKnownNotations) {
            PGPainless.getPolicy().notationRegistry.addKnownNotation(notation)
        }

        return 0
    }

    companion object {

        @JvmStatic
        fun main(args: Array<String>): Unit = exitProcess(
            execute(args)
        )

        @JvmStatic
        fun execute(args: Array<String>): Int {
            return CommandLine(WotCLI()).execute(*args)
        }

        @JvmStatic
        val gpgHelper = GpgHelper("/usr/bin/gpg")
    }

    override fun toString(): String {
        val source = if (optKeyRing.optGpg) {
            "gpg"
        } else {
            optKeyRing.optPgpCertD ?: optKeyRing.optKeyring?.contentToString() ?: "null"
        }
        return "trustroot=${trustRoots}, source=$source, gossip=$optGossip, amount=${optTrustAmount.get(optCertificationNetwork)}," +
                " referenceTime=${optReferenceTime.timestamp}, notations=${optKnownNotations.contentToString()}"
    }
}
