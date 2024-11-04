# Trust 

Trust module main responsability is to provide cryptographic material, metadata and revocation status of parties involved in the [OpnedID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocol.
Users can define their own trust module by realizing and configuring a class that satisfy the interface [pyeudiw.trust.interface.TrustEvaluator](/pyeudiw/trust/interface.py).
This project includes some default implementation of trust, whose configuration are described below.

## Configuration of default Trust modules

### Direct Trust for SD-JWT VC

Module `pyeudiw.trust.default.direct_trust_sd_jwt_vc` provides a source of direct trust that can be used to validate VP tokens with format [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html).

The configuration parameters of the module are the following.

| Parameter        | Description                                                             | Example Value              |
| ---------------- | ----------------------------------------------------------------------- | -------------------------- |
| jwk_endpoint     | Path component of the endpoint where JWT issuer metadata can be fetched | /.well-known/jwt-vc-issuer |
| cache_ttl        | (Optional) Maximum time (in seconds) of a cached jwk; use 0 to disable  | 60                         |
| httpc_parameters | (Optional) Parameters of the HTTP connection of the request above       | (see below)                |

HTTPC parameters are optional and described below.

| Parameter               | Description                                                                 |
| ----------------------- | --------------------------------------------------------------------------- |
| httpc_params.connection | dictionary that represents a `aiohttp._RequestOptions` used in GET requests |
| httpc_params.session    | dictionary that represents the keyword arguments of `aiohttp.ClientSession` |

Some HTTPC parameters are commonly used, have a default value and as an alternative can be optionally defined by an environment variable.

| Parameter                    | Description                                                     | Default Value | Environment Variable  |
| ---------------------------- | --------------------------------------------------------------- | ------------- | --------------------- |
| httpc_params.connection.ssl  | The flag to indicate whether to use SSL for the HTTP connection | true          | PYEUDIW_HTTPC_SSL     |
| httpc_params.session.timeout | The timeout value for the HTTP session                          | 6             | PYEUDIW_HTTPC_TIMEOUT |

### Federation

Module `pyeudiw.trust.default.federation` provides a source of trusted entities and metadata based on [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) that is intended to be applicable to Issuer, Holders and Verifiers. In the specific case of the Verifier (this application), the module can expose verifier metadata at the `.well-known/openid-federation` endpoint.

The configuration parameters of the module are the following.


| Parameter                                                      | Description                                               | Example Value                                                            |
| -------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------ |
| config.federation.metadata_type                                | The type of metadata to use for the federation            | wallet_relying_party                                                     |
| config.federation.authority_hints                              | The list of authority hints to use for the federation     | [http://127.0.0.1:10000]                                                 |
| config.federation.trust_anchors                                | The list of trust anchors to use for the federation       | [http://127.0.0.1:10000]                                                 |
| config.federation.default_sig_alg                              | The default signature algorithm to use for the federation | RS256                                                                    |
| config.federation.federation_entity_metadata.organization_name | The organization name                                     | Developers Italia SATOSA OpenID4VP backend policy_uri, tos_uri, logo_uri |
| config.federation.federation_entity_metadata.homepage_uri      | The URI of the homepage                                   | https://developers.italia.it                                             |
| config.federation.federation_entity_metadata.policy_uri        | The URI of the policy                                     | https://developers.italia.it/policy.html                                 |
| config.federation.federation_entity_metadata.tos_uri           | The URI of the TOS                                        | https://developers.italia.it/tos.html                                    |
| config.federation.federation_entity_metadata.logo_uri          | The URI of the logo                                       | https://developers.italia.it/assets/icons/logo-it.svg                    |
| config.federation.federation_jwks                              | The list of (private) JSON Web Keys for the federation    |                                                                          |
