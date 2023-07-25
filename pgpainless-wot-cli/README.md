<!--
SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Command Line Interface for the Web-of-Trust

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/pgpainless-wot-cli)](https://search.maven.org/artifact/org.pgpainless/pgpainless-wot-cli)

This module contains a command line interface application that acts as a front-end for
[`pgpainless-wot`](../pgpainless-wot).
The interface of the application is modelled after the [sq-wot](https://gitlab.com/sequoia-pgp/sequoia-wot/)
reference implementation.

## Build

To build the application, navigate into this subdirectory and execute the following command:
```shell
../gradlew installDist
```

A ready-to-use distributable directory can then be found in `build/install/` with an executable in `build/install/pgpainless-wot-cli/bin/`.