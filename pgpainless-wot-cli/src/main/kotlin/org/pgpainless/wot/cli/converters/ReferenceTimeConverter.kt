// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.converters

import org.pgpainless.util.DateUtil
import org.pgpainless.wot.network.ReferenceTime
import picocli.CommandLine.ITypeConverter

class ReferenceTimeConverter: ITypeConverter<ReferenceTime> {

    override fun convert(value: String?): ReferenceTime {
        if (value == null) {
            return ReferenceTime.now()
        }
        return ReferenceTime.timestamp(DateUtil.parseUTCDate(value))
    }
}