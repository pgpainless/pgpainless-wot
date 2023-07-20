// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli

import org.pgpainless.PGPainless
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Root
import pgp.certificate_store.PGPCertificateStore

class GpgHelper(val executable: String) {

    fun readGpgKeyRing(): PGPCertificateStore {
        return KeyRingCertificateStore(
            PGPainless.readKeyRing().publicKeyRingCollection(
                Runtime.getRuntime().exec("$executable --export").inputStream
            )
        )
    }

    fun readGpgOwnertrust(): List<Root> = Runtime.getRuntime()
        .exec("$executable --export-ownertrust")
        .inputStream
        .bufferedReader()
        .readLines()
        .asSequence()
        .filterNot { it.startsWith("#") }
        .filterNot { it.isBlank() }
        .map {
            Fingerprint(it.substring(0, it.indexOf(':'))) to it.elementAt(it.indexOf(':') + 1) }
        .map {
            it.first to when (it.second.digitToInt()) {
                2 -> null   // unknown
                3 -> 0      // not trust
                4 -> 40     // marginally trusted
                5 -> 120    // fully trusted
                6 -> Int.MAX_VALUE    // ultimately trusted
                else -> null
            }
        }
        .filterNot { it.second == null }
        .map {
            Root(it.first, it.second!!)
        }
        .toList()
}