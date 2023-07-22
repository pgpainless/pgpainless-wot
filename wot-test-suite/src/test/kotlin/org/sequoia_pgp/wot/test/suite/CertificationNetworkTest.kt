// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.test.suite

import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.sequoia_pgp.wot.test.ExecutionCallback
import org.sequoia_pgp.wot.test.TestCase
import org.sequoia_pgp.wot.vectors.CertificationNetworkVectors

class CertificationNetworkTest: TestCase(CertificationNetworkVectors()) {

    private val v = vectors as CertificationNetworkVectors

    @ParameterizedTest
    @MethodSource("instances")
    fun `without --certification-network Alice can only authenticate Bob`(callback: ExecutionCallback) {
        val bobArgs = "-k ${keyRingPath()} -r ${v.aliceFpr} -a 120 authenticate ${v.bobFpr} ${v.bobUid}".split(" ").toTypedArray()
        val carolArgs = "-k ${keyRingPath()} -r ${v.aliceFpr} -a 120 authenticate ${v.carolFpr} ${v.carolUid}".split(" ").toTypedArray()
        val daveArgs = "-k ${keyRingPath()} -r ${v.aliceFpr} -a 120 authenticate ${v.daveFpr} ${v.daveUid}".split(" ").toTypedArray()

        val bobOutput = """[✓] A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05 <bob@example.org>: fully authenticated (100%)
  ◯ B2B371214EF71AFD16E42C62D81360B4C0489225 ("<alice@example.org>")
  │   certified the following binding on 2023-01-19
  └ A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05 "<bob@example.org>"

"""
        val noOutput = """No paths found.
"""

        assertResultEquals(callback, bobArgs, bobOutput, 0)
        assertResultEquals(callback, carolArgs, noOutput, 1)
        assertResultEquals(callback, daveArgs, noOutput, 1)
    }

    @ParameterizedTest
    @MethodSource("instances")
    fun `with --certification-network Alice can authenticate all`(callback: ExecutionCallback) {
        val bobArgs = "-k ${keyRingPath()} -r ${v.aliceFpr} -a 120 --certification-network authenticate ${v.bobFpr} ${v.bobUid}".split(" ").toTypedArray()
        val carolArgs = "-k ${keyRingPath()} -r ${v.aliceFpr} -a 120 --certification-network authenticate ${v.carolFpr} ${v.carolUid}".split(" ").toTypedArray()
        val daveArgs = "-k ${keyRingPath()} -r ${v.aliceFpr} -a 120 --certification-network authenticate ${v.daveFpr} ${v.daveUid}".split(" ").toTypedArray()

        val bobOutput = """[✓] A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05 <bob@example.org>: fully authenticated (100%)
  ◯ B2B371214EF71AFD16E42C62D81360B4C0489225 ("<alice@example.org>")
  │   certified the following binding on 2023-01-19
  └ A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05 "<bob@example.org>"

"""
        val carolOutput = """[✓] AB9EF1C89631519842ED559697557DD147D99C97 <carol@example.org>: fully authenticated (100%)
  ◯ B2B371214EF71AFD16E42C62D81360B4C0489225 ("<alice@example.org>")
  │   certified the following certificate on 2023-01-19
  ├ A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05 ("<bob@example.org>")
  │   certified the following binding on 2023-01-19
  └ AB9EF1C89631519842ED559697557DD147D99C97 "<carol@example.org>"

"""
        val daveOutput = """[✓] 9A1AE937B5CB8BC46048AB63023CC01973ED9DF3 <dave@example.org>: fully authenticated (100%)
  ◯ B2B371214EF71AFD16E42C62D81360B4C0489225 ("<alice@example.org>")
  │   certified the following certificate on 2023-01-19
  ├ A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05 ("<bob@example.org>")
  │   certified the following certificate on 2023-01-19
  ├ AB9EF1C89631519842ED559697557DD147D99C97 ("<carol@example.org>")
  │   certified the following binding on 2023-01-19
  └ 9A1AE937B5CB8BC46048AB63023CC01973ED9DF3 "<dave@example.org>"

"""

        assertResultEquals(callback, bobArgs, bobOutput, 0)
        assertResultEquals(callback, carolArgs, carolOutput, 0)
        assertResultEquals(callback, daveArgs, daveOutput, 0)
    }
}