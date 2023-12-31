// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Identifier

/**
 * This test is similar to the `multiple-userids` tests, but the two
 * certifications are for the same User ID and key.  This works if the
 * certifications have the same timestamp.
 *
 * There is also an old certification, which should be ignored.
 *
 * ```
 *                     alice
 *        50/2    /      |  70/1   \  old and ignored
 *                \      |         /  120/255
 *                      bob
 *                       | 120/2
 *                     carol
 *                       | 120
 *                     dave
 * ```
 */
class MultipleCertifications1Vectors: ArtifactVectors {

    val aliceFpr = Identifier("9219941467AA737C6EC1207959A2CEFC112C359A")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Identifier("72CAA0F0A4A020F5FA20CD8CB5CC04473AA88123")
    val bobUid = "<bob@example.org>"
    // Certified by: 9219941467AA737C6EC1207959A2CEFC112C359A
    // Certified by: 9219941467AA737C6EC1207959A2CEFC112C359A
    // Certified by: 9219941467AA737C6EC1207959A2CEFC112C359A

    val carolFpr = Identifier("853304031E7B0B116BBD0B398734F11945313904")
    val carolUid = "<carol@example.org>"
    // Certified by: 72CAA0F0A4A020F5FA20CD8CB5CC04473AA88123

    val daveFpr = Identifier("4C77ABDBE4F855E0C3C7A7D549F6B2BFDA83E424")
    val daveUid = "<dave@example.org>"
    // Certified by: 853304031E7B0B116BBD0B398734F11945313904

    /**
     * A few moments after the network has been generated.
     */
    val t0 = parseReferenceTime("2021-10-06 12:20:00 UTC")

    override val tempFilePrefix: String
        get() = "multiple-certifications-1"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/multiple-certifications-1.pgp"
    }
}