// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.converters

import org.pgpainless.wot.network.Identifier
import picocli.CommandLine.ITypeConverter

class FingerprintConverter: ITypeConverter<Identifier> {

    override fun convert(value: String?): Identifier? {
        return when(value) {
            null -> null
            else -> Identifier(value)
        }
    }
}