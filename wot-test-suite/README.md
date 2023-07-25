<!--
SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: BSD-3-Clause
-->

# WoT Test Suite

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/wot-test-suite)](https://search.maven.org/artifact/org.pgpainless/wot-test-suite)

This module contains test vectors (PGP Keyring files) from [Sequoia-WOT](https://gitlab.com/sequoia-pgp/sequoia-wot/-/tree/main/tests/data)
which are licensed under the [3-Clause BSD License](https://opensource.org/license/bsd-3-clause/).

Kotlin wrappers have been added around the PGP files for easy access.

JUnit tests in `src/test/kotlin/org/pgpainless/wot/query/` are ported from Sequoia-WOT and are therefore licensed under the LGPL-v2.