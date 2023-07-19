<!--
SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: CC0-1.0
-->
# OpenPGP Web-of-Trust

An implementation of the [OpenPGP Web of Trust](https://sequoia-pgp.gitlab.io/sequoia-wot/) using [PGPainless](https://pgpainless.org).

## Module Overview
* [wot-dijkstra](wot-dijkstra) focuses on the path-finding aspects of the Web-of-Trust
* [pgpainless-wot](pgpainless-wot) handles parsing OpenPGP certificates and network construction
* [pgpainless-wot-cli](pgpainless-wot-cli) implements a CLI layer over `pgpainless-wot` and `wot-dijkstra`
* [sequoia-wot-vectors](sequoia-wot-vectors) contains test vectors ported from [Sequoia-PGP](https://sequoia-pgp.org)s Web-of-Trust implementation [sq-wot](https://gitlab.com/sequoia-pgp/sequoia-wot).

## Acknowledgements

This project has been [funded](https://nlnet.nl/project/PGPainless/) by [NGI Assure](https://nlnet.nl/assure/) through [NLNet](https://nlnet.nl).  
NGI Assure is made possible with financial support from the [European Commission](https://ec.europa.eu/)'s [Next Generation Internet](https://ngi.eu/) programme, under the aegis of [DG Communications Networks, Content and Technology](https://ec.europa.eu/info/departments/communications-networks-content-and-technology_en).
[![NGI Assure Logo](https://blog.jabberhead.tk/wp-content/uploads/2022/05/NGIAssure_tag.svg)](https://nlnet.nl/assure/)
