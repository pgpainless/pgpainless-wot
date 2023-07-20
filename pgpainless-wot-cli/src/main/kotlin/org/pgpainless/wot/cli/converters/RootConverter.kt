// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.converters

import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Root
import picocli.CommandLine.ITypeConverter

class RootConverter: ITypeConverter<Root> {
    override fun convert(value: String?): Root? {
        return when(value) {
            null -> null
            else -> Root(Fingerprint(value))
        }
    }
}