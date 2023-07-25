<!--
SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Web-of-Trust + PGPainless

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/pgpainless-wot)](https://search.maven.org/artifact/org.pgpainless/pgpainless-wot)

This module plugs PGPainless as an OpenPGP backend into [`wot-dijkstra`](../wot-dijkstra) to implement the
[Web of Trust](https://sequoia-pgp.gitlab.io/sequoia-wot/).

For a command line interface, check out [`pgpainless-wot-cli`](../pgpainless-wot-cli).