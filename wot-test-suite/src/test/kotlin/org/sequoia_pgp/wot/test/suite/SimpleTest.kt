// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.test.suite

import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.sequoia_pgp.wot.test.ExecutionCallback
import org.sequoia_pgp.wot.test.TestCase
import org.sequoia_pgp.wot.vectors.SimpleVectors

class SimpleTest: TestCase(SimpleVectors()) {

    private val v = vectors as SimpleVectors

    @ParameterizedTest
    @MethodSource("instances")
    fun cannotAuthenticateEllenWithA100(callback: ExecutionCallback) {
        val expected = """No paths found.
"""
        val args = "-k ${keyRingPath()} -r ${v.aliceFpr} -a 100 authenticate ${v.ellenFpr} ${v.ellenUid}".split(" ")
        assertResultEquals(callback, args.toTypedArray(), expected, 1)
    }

    @ParameterizedTest
    @MethodSource("instances")
    fun canAuthenticateEllenWithCertificationNetworkA100(callback: ExecutionCallback) {
        val expected = """[✓] A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4 <ellen@example.org>: partially authenticated (83%)
  ◯ 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D ("<alice@example.org>")
  │   partially certified (amount: 100 of 120) the following certificate on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) meta-introducer (depth: 2)
  ├ 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90 ("<bob@example.org>")
  │   partially certified (amount: 100 of 120) the following certificate on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) introducer (depth: 1)
  ├ 43530F91B450EDB269AA58821A1CF4DC7F500F04 ("<carol@example.org>")
  │   partially certified (amount: 100 of 120) the following certificate on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) introducer (depth: 1)
  ├ 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281 ("<dave@example.org>")
  │   partially certified (amount: 100 of 120) the following binding on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) introducer (depth: 1)
  └ A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4 "<ellen@example.org>"

"""
        val args = "--certification-network -k ${keyRingPath()} -r ${v.aliceFpr} -a 100 authenticate ${v.ellenFpr} ${v.ellenUid}".split(" ")
        assertResultEquals(callback, args.toTypedArray(), expected, 0)
    }
}