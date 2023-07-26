// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.policy.Policy
import org.pgpainless.util.DateUtil
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.PGPNetworkParser
import org.pgpainless.wot.network.Network
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.*
import kotlin.io.path.outputStream

interface ArtifactVectors {

    val tempFilePrefix: String

    val tempKeyRingFile: File
        get() {
            val path = Files.createTempFile(tempFilePrefix, ".pgp")

            val outputStream = path.outputStream()
            Streams.pipeAll(keyRingInputStream(), outputStream)
            outputStream.close()

            val file = path.toFile()
            file.deleteOnExit()
            return file
        }

    private fun parseDate(string: String): Date {
        return try {
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss z")
                    .apply { timeZone = TimeZone.getTimeZone("UTC") }
                    .parse(string)
        } catch (e: ParseException) {
            SimpleDateFormat("yyyy-MM-dd")
                    .apply {timeZone = TimeZone.getTimeZone("UTC") }
                    .parse(string)
        } catch (e: ParseException) {
            throw IllegalArgumentException(e)
        }
    }

    fun parseReferenceTime(string: String): Date {
        return DateUtil.parseUTCDate(string)
    }

    fun getResourceName(): String

    fun getNetworkAt(referenceTime: Date = Date(), policy: Policy = PGPainless.getPolicy()): Network {
        val inputStream = keyRingInputStream()
        val keyRing = PGPainless.readKeyRing().publicKeyRingCollection(inputStream)
        val store = KeyRingCertificateStore(keyRing)
        return PGPNetworkParser(store).buildNetwork(policy, referenceTime)
    }

    fun keyRingInputStream(): InputStream {
        return ArtifactVectors::class.java.classLoader.getResourceAsStream(getResourceName())!!
    }




}