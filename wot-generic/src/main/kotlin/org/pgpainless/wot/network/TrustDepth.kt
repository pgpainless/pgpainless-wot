// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import java.lang.IllegalArgumentException

class TrustDepth: Comparable<Int> {
    val value: Int

    private constructor(value: Int) {
        this.value = when (value) {
            in validRange -> value
            else -> throw IllegalArgumentException("Trust Depth MUST be a value from 0 to 255.")
        }
    }

    fun isUnlimited(): Boolean {
        return value == 255
    }

    fun reduce(trustDepth: Int): TrustDepth {
        if (isUnlimited()) {
            return unlimited()
        }
        require(value - trustDepth >= 0)
        return limited(value - trustDepth)
    }

    fun min(other: TrustDepth): TrustDepth {
        return when ((isUnlimited() to other.isUnlimited())) {
            Pair(true, true) -> this
            Pair(true, false) -> other
            Pair(false, true) -> this
            else -> if (compareTo(other.value) < 1)
                this
            else
                other
        }
    }

    companion object {
        @JvmStatic
        private val validRange = 0..255

        @JvmStatic
        fun unlimited(): TrustDepth {
            return TrustDepth(255)
        }

        @JvmStatic
        fun limited(value: Int): TrustDepth {
            require(value >= 0)
            require(value < 255)
            return TrustDepth(value)
        }

        @JvmStatic
        fun auto(value: Int): TrustDepth {
            return TrustDepth(value)
        }
    }

    override fun compareTo(other: Int): Int {
        if (isUnlimited()) {
            return 1
        }
        return value.compareTo(other)
    }

    override fun toString(): String {
        if (isUnlimited()) return "unconstrained"
        return value.toString()
    }
}