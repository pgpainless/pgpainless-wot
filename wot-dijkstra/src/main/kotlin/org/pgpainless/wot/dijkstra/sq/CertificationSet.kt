// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

/**
 * A [CertificationSet] is a set of [Certifications][Certification] made by the same issuer, on the same
 * target certificate.
 * In some sense, a [CertificationSet] can be considered an edge in the web of trust.
 *
 * @param issuer synopsis of the certificate that issued the [Certifications][Certification]
 * @param target synopsis of the certificate that is targeted by the [Certifications][Certification]
 * @param certifications [MutableMap] keyed by user-ids, whose values are [MutableLists][MutableList] of
 * [Certifications][Certification] that are calculated over the key user-id. Note, that the key can also be null for
 * [Certifications][Certification] over the targets primary key.
 */
data class CertificationSet(
        val issuer: CertSynopsis,
        val target: CertSynopsis,
        val certifications: MutableMap<String?, MutableList<Certification>>) {

    companion object {

        /**
         * Create an empty [CertificationSet].
         *
         * @param issuer the certificate that issued the [Certifications][Certification].
         * @param target the certificate that is targeted by the [Certifications][Certification].
         */
        @JvmStatic
        fun empty(issuer: CertSynopsis, target: CertSynopsis): CertificationSet {
            return CertificationSet(issuer, target, HashMap())
        }

        /**
         * Create a [CertificationSet] from a single [Certification].
         *
         * @param certification certification
         */
        @JvmStatic
        fun fromCertification(certification: Certification): CertificationSet {
            val set = empty(certification.issuer, certification.target)
            set.add(certification)
            return set
        }
    }

    /**
     * Merge the given [CertificationSet] into this.
     * This method copies all [Certifications][Certification] from the other [CertificationSet] into [certifications].
     *
     * @param other [CertificationSet] with the same issuer fingerprint and target fingerprint as this object.
     */
    fun merge(other: CertificationSet) {
        if (other == this) {
            return
        }

        require(issuer.fingerprint == other.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == other.target.fingerprint) { "Target fingerprint mismatch." }

        for (userId in other.certifications.keys) {
            for (certification in other.certifications[userId]!!) {
                add(certification)
            }
        }
    }

    /**
     * Add a single [Certification] into this objects [certifications].
     *
     * @param certification [Certification] with the same issuer fingerprint and target fingerprint as this object.
     */
    fun add(certification: Certification) {
        require(issuer.fingerprint == certification.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == certification.target.fingerprint) { "Target fingerprint mismatch." }

        var certificationsForUserId: MutableList<Certification>? = certifications[certification.userId]
        if (certificationsForUserId == null) {
            certificationsForUserId = ArrayList()
            certifications[certification.userId] = certificationsForUserId
        }
        certificationsForUserId.add(certification)
    }

    override fun toString(): String {
        return certifications.map { it.value }.flatten().joinToString("\n")
    }
}