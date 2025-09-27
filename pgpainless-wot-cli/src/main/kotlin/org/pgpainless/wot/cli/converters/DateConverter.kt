// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.converters

import java.util.*
import org.pgpainless.util.DateUtil
import picocli.CommandLine.ITypeConverter

class DateConverter : ITypeConverter<Date> {

    override fun convert(value: String?): Date {
        if (value == null) {
            return Date()
        }
        return DateUtil.parseUTCDate(value)
    }
}
