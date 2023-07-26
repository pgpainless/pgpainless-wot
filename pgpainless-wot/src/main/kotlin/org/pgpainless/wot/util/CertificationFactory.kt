// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.util

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.wot.network.Edge
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.network.RegexSet
import org.pgpainless.wot.network.RegexSet.Companion.fromExpressions
import org.pgpainless.wot.network.TrustDepth

class CertificationFactory {

    companion object {
        @JvmStatic
        fun fromDelegation(issuer: Node,
                           target: Node,
                           signature: PGPSignature): Edge.Component {
            return Edge.Delegation(issuer,
                    target,
                    SignatureSubpacketsUtil.getSignatureCreationTime(signature)!!.time,
                    SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature),
                    SignatureSubpacketsUtil.isExportable(signature),
                    getTrustAmountFrom(signature),
                    getTrustDepthFrom(signature),
                    regexSetFrom(signature)
            )
        }

        @JvmStatic
        fun fromCertification(issuer: Node,
                              target: Node,
                              targetUserId: String,
                              signature: PGPSignature): Edge.Component {
            return Edge.Certification(issuer,
                    target,
                    targetUserId,
                    SignatureSubpacketsUtil.getSignatureCreationTime(signature)!!.time,
                    SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature),
                    SignatureSubpacketsUtil.isExportable(signature),
                    getTrustAmountFrom(signature),
                    getTrustDepthFrom(signature),
                    regexSetFrom(signature))
        }

        @JvmStatic
        private fun getTrustAmountFrom(signature: PGPSignature): Int {
            if (signature.signatureType in intArrayOf(PGPSignature.KEY_REVOCATION, PGPSignature.CERTIFICATION_REVOCATION)) {
                return 0
            }
            val packet = SignatureSubpacketsUtil.getTrustSignature(signature)
            return packet?.trustAmount ?: 120
        }

        @JvmStatic
        private fun getTrustDepthFrom(signature: PGPSignature): TrustDepth {
            if (signature.signatureType in intArrayOf(PGPSignature.KEY_REVOCATION, PGPSignature.CERTIFICATION_REVOCATION)) {
                return TrustDepth.limited(0)
            }
            val packet = SignatureSubpacketsUtil.getTrustSignature(signature)
            return TrustDepth.auto(packet?.depth ?: 0)
        }

        @JvmStatic
        private fun regexSetFrom(signature: PGPSignature): RegexSet {
            val regexList = SignatureSubpacketsUtil.getRegularExpressions(signature)
            val stringList: MutableList<String> = mutableListOf()
            regexList.mapTo(stringList) { it.regex }
            return fromExpressions(stringList)
        }
    }
}