# eudi-wallet-it-python

![CI build](https://github.com/italia/eudi-wallet-it-python/workflows/pyeudiw/badge.svg)
![Python version](https://img.shields.io/badge/license-Apache%202-blue.svg)
![py-versions](https://img.shields.io/badge/python-3.10-blue.svg)
[![GitHub issues](https://img.shields.io/github/issues/italia/eudi-wallet-it-python.svg)](https://github.com/italia/eudi-wallet-it-python/issues)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![Join the #spid openid](https://img.shields.io/badge/Slack%20channel-%23spid%20openid-blue.svg)](https://developersitalia.slack.com/archives/C7E85ED1N/)

The EUDI Wallet Python toolchain is a suite of Python libraries designed to
make it easy the implementation of an EUDI Wallet Relying Party according 
to the [Italian Wallet implementation profile](https://italia.github.io/eudi-wallet-it-docs/versione-corrente/en/).

The toolchain contains the following components:

| Name | Description |
| :--- | --- |
| __jwk__ | JSON Web Key (JWK) according to [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517). | 
| __jwt__ | Signed and encrypted JSON Web Token (JWT) according to [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519), [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515) and [RFC7516](https://datatracker.ietf.org/doc/html/rfc7516) | 
| __tools.qrcode__ | QRCodes creation | 
| __oauth2.dpop__ | Tools for issuing and parsing DPoP artifacts, according to [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop) |
| __federation__ | Trust evaluation mechanisms, according to [OpenID Connect Federation 1.0](https://openid.net/specs/openid-connect-federation-1_0.html) |
| __trust__ | Helper classes to handle both X.509 and OIDC Federation trust evaluation mechanisms |
| __satosa.backend__ | SATOSA Relying Party backend, according to [OpenID for Verifiable Presentations](https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html) |
| __openid4vp__ | Classes and schemas related to [OpenID for Verifiable Presentations](https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html) |
| __presentation_exchange__ | Resources related to [DiF Presentation Exchange](https://identity.foundation/presentation-exchange/) |
| __sd_jwt__ | Issuance and verification of SD-JWT according to [Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) |


## Setup

Install enviroment and dependencies
````
sudo apt install python3-dev python3-pip git
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install virtualenv
````

Activate the environment. It's optional and up to you if you want to install 
in a separate env or system wide
````
virtualenv -p python3 env
source env/bin/activate
````

Install using pip:

`pip install pyeudiw` or `pip install pyeudiw[satosa]` for the satosa backend.

Install using github:

`pip install git+https://github.com/italia/eudi-wallet-it-python`


## Usage

TBD. Here a section that points to the documentation of each single package and some common example about their usage for some specific tasks.

| Name | Description |
| :--- | --- |
| __jwk__ | link to the API documentation [](). | 
| __jwt__ | link to the API documentation [](). | 
| __tools.qrcode__ | QRCodes creation. | 
| __oauth2.dpop__ | link to the API documentation [](). |
| __federation__ | link to the API documentation [](). |
| __trust__ | link to the API documentation [](). |
| __satosa.backend__ | link to the API documentation [](). |
| __openid4vp__ | link to the API documentation [](). |
| __presentation_exchange__ | link to the API documentation [](). |
| __sd_jwt__ | link to the API documentation [](). |


## Example project

The example project is a docker-compose that runs a demo composed by the following component:

- Wordpress with SAML2 support and Bootstrap Italia template preregistered to the IAM Proxy.
- [Satosa-Saml2Spid](https://github.com/italia/Satosa-Saml2Spid) IAM Proxy with a preconfigured OpenID4VP backend.

Please read [this README](example/README.Wordpress.md) to get a fully working Wordpress setup with SAML2 support.


## SatoSa configuration

[SaToSa](https://github.com/IdentityPython/SATOSA) is a general purpose IAM 
proxy solution that allows interoperability between different entities that implements different
authentication protocols such as SAML2, OpenID Connect and OAuth2. This project offers a SaToSa
backend to enable the OpenID4VP protocol. 

<img src="docs/gallery/iam-proxy.svg" width="512">

Please read this [README](README.SATOSA.md) any details about how to configure SaToSa with the OpenID4VP Relying Party backend.


## Contribute

Your contribution is welcome, no question is useless and no answer is obvious, we need you.


### Contribute as end user

Please open an issue if you've found a bug or if you want to ask some features.


### Contribute as developer

Please open your Pull Requests on the __dev__ branch. 
Please consider the following branches:

 - __main__: where we merge the code before tag a new stable release.
 - __dev__: where we push our code during development.
 - __other-custom-name__: where a new feature/contribution/bugfix will be handled, revisioned and then merged to dev branch.


## Authors

- Giuseppe De Marco
- Pasquale De Rose
- Alessio Murru
- Salvatore Laiso
- Nicola Saitto
