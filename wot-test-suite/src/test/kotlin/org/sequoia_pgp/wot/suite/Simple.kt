// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite

import org.sequoia_pgp.wot.vectors.SimpleVectors

class Simple: SimpleTestCase(SimpleVectors()) {
    override fun arguments(): Array<String> {
        val v = vectors as SimpleVectors
        return arrayOf("-k", keyRingPath(), "--certification-network", "-r", v.aliceFpr.toString(), "-a", "100", "authenticate", v.ellenFpr.toString(), v.ellenUid)
    }

    override fun expectedOutput(): Pair<String, Int> {
        return """AB65713B2D0ABFC5A4F28BC10C9CE4A699D8D authenticate A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4 "<ellen@example.org>"
[✓] A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4 <ellen@example.org>: partially authenticated (83%)
  ◯ 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D ("<alice@example.org>")
  │   partially certified (amount: 100 of 120) the following certificate on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) meta-introducer (depth: 2)
  ├ 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90 ("<bob@example.org>")
  │   partially certified (amount: 100 of 120) the following certificate on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) introducer (depth: 1)
  ├ 43530F91B450EDB269AA58821A1CF4DC7F500F04 ("<carol@example.org>")
  │   partially certified (amount: 100 of 120) the following certificate on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) introducer (depth: 1)
  ├ 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281 ("<dave@example.org>")
  │   partially certified (amount: 100 of 120) the following binding on 2021-10-05 (expiry: 2026-10-05) as a partially trusted (100 of 120) introducer (depth: 1)
  └ A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4 "<ellen@example.org>"

""" to 0
    }
}