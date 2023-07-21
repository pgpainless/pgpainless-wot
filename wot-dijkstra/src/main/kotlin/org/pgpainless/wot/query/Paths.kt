// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

/**
 * List of individual [Paths][Path].
 *
 * @param _paths list of paths
 */
class Paths(private val _paths: MutableMap<Path, Int>) {

    /**
     * Empty collection of paths.
     */
    constructor(): this(mutableMapOf<Path, Int>())

    val paths: List<Path>
        get() {
            return _paths.keys.toList()
        }

    val items: List<Map.Entry<Path, Int>>
        get() = _paths.entries.toList()

    /**
     * Add a [Path] to the list.
     *
     * @param path path to add
     * @param amount effective amount of the path (might be smaller than the paths actual amount)
     * @throws IllegalArgumentException if the given amount is smaller or equal to the paths trust amount.
     */
    fun add(path: Path, amount: Int) {
        require(amount <= path.amount) {
            "Effective amount cannot exceed actual amount of the path."
        }
        _paths[path] = amount
    }

    /**
     * The summed trust amount of all paths in this collection.
     */
    val amount: Int
        get() {
            return _paths.values.sumOf { it }
        }
}