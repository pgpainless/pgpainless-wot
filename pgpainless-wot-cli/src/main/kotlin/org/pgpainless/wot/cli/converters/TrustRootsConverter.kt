// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.converters

import org.pgpainless.wot.network.Identifier
import org.pgpainless.wot.network.TrustRoot
import picocli.CommandLine.ITypeConverter

class TrustRootsConverter: ITypeConverter<TrustRoot> {
    override fun convert(value: String?): TrustRoot? {
        return when(value) {
            null -> null
            else -> TrustRoot(Identifier(value))
        }
    }
}