// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.converters

import org.pgpainless.wot.network.Fingerprint
import picocli.CommandLine.ITypeConverter

class FingerprintConverter: ITypeConverter<Fingerprint> {

    override fun convert(value: String?): Fingerprint? {
        return when(value) {
            null -> null
            else -> Fingerprint(value)
        }
    }
}