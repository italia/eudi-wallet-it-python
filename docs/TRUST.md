# Trust

# Trust Module

## Caching modes

There are two caching modes that can be used to store the cryptographic material of the parties involved in the protocol.

- update_first: The cryptographic material is fetched using the handler protocol and then stored in the cache.
  If the retrieval fails, the cache is used.
- cache_first: The cryptographic material is fetched using the cache.
  If the cache is empty, the handler protocol is used to retrieve the cryptographic material and then stored in the cache and returned.

update_first is the default caching mode.
You can set the caching mode by setting the variable trust_caching_mode in the configuration file.

## Configuration of default Trust modules

The main responsibility of the Trust module is to provide cryptographic material, metadata, trust parameters, and revocation status of parties involved in the [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocol. This project includes some default implementations of trust, whose configurations are described below.

> [!NOTE]
> A trust parameter is a piece of information that can be used to evaluate the trustworthiness of an entity. For example, the trust parameter of an OpenID Federation entity is the [trust chain](https://openid.net/specs/openid-federation-1_0.html#section-4) of the entity.

### Direct Trust for SD-JWT VC

The module `pyeudiw.trust.default.direct_trust_sd_jwt_vc` provides a source of direct trust that can be used to validate VP tokens with the format [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html).

#### Configuration Parameters

| Parameter        | Description                                                             | Example Value              |
| ---------------- | ----------------------------------------------------------------------- | -------------------------- |
| jwk_endpoint     | Path component of the endpoint where JWT issuer metadata can be fetched | /.well-known/jwt-vc-issuer |
| cache_ttl        | (Optional) Maximum time (in seconds) of a cached jwk; use 0 to disable  | 60                         |
| httpc_parameters | (Optional) Parameters of the HTTP connection of the request above       | (see below)                |

#### HTTPC Parameters

HTTPC parameters are optional and described below.

| Parameter               | Description                                                                   |
| ----------------------- | ----------------------------------------------------------------------------- |
| httpc_params.connection | Dictionary that represents a `aiohttp._RequestOptions` used in GET requests |
| httpc_params.session    | Dictionary that represents the keyword arguments of `aiohttp.ClientSession` |

Some HTTPC parameters are commonly used, have a default value, and can alternatively be defined by an [environment variable](https://github.com/italia/eudi-wallet-it-python/blob/dev/README.SATOSA.md).

### Federation

The module `pyeudiw.trust.handler.federation` provides a source of trusted entities and metadata based on [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html). It is intended to be applicable to Issuers, Holders, and Verifiers. Specifically, for the Verifier (this application), the module can expose verifier metadata at the `.well-known/openid-federation` endpoint.

| Parameter                                                      | Description                                               | Example Value                                                    |
| -------------------------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------- |
| config.federation.metadata_type                                | The type of metadata to use for the federation            | openid_credential_verifier                                       |
| config.federation.authority_hints                              | The list of authority hints to use for the federation     | [http://127.0.0.1:10000]                                         |
| config.federation.trust_anchors                                | The list of trust anchors to use for the federation       | [http://127.0.0.1:10000]                                         |
| config.federation.default_sig_alg                              | The default signature algorithm to use for the federation | RS256                                                            |
| config.federation.federation_entity_metadata.organization_name | The organization name                                     | IAM Proxy Italia OpenID4VP backend policy_uri, tos_uri, logo_uri |
| config.federation.federation_entity_metadata.homepage_uri      | The URI of the homepage                                   | https://developers.italia.it                                     |
| config.federation.federation_entity_metadata.policy_uri        | The URI of the policy                                     | https://developers.italia.it/policy.html                         |
| config.federation.federation_entity_metadata.tos_uri           | The URI of the TOS                                        | https://developers.italia.it/tos.html                            |
| config.federation.federation_entity_metadata.logo_uri          | The URI of the logo                                       | https://developers.italia.it/assets/icons/logo-it.svg            |
| config.federation.federation_jwks                              | The list of (private) JSON Web Keys for the federation    |                                                                  |

### X509

The module `pyeudiw.trust.handler.x509` provides a source of trusted entities based on X509 chain.

| Parameter                                          | Description                                                                                                                                                                                                                                                                                                                                              | Example Value |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| config.x509.client_id_scheme                       | The scheme in the client id used in the request                                                                                                                                                                                                                                                                                                         | x509_san_dns  |
| config.x509.certificate_authorities                | It's a list of trusted certificate authorities composed of dict where the key is the DNS, the URI or the CN of<br />the certificate and the value a x509 certificate in PEM or DER Format.                                                                                                                                                             |               |
| config.x509.relying_party_certificate_chains_by_ca | It's an object containing the chain's relative to the certificate authorities listed in certificate_authorities parameter and<br /> must be relative to the RP. In particular leaf certificate's DNS, the URI or the CN must match the client id and <br />must be related to metadata_jwks[0].<br />The certificates can be in PEM or DER Format. |               |

## Write a Custom Trust Handler Module

Users can define their own trust module by implementing and configuring a class that satisfies the interface [TrustHandlerInterface](/pyeudiw/trust/handler/interface.py).

The handler works with the trust information of an entity, such as the public key, metadata, trust parameters, and revocation status using the class [TrustSource](/pyeudiw/trust/model/trust_source.py). This class is used by the `CombinedTrustEvaluator` to store the trust information of an entity in the database using the database module.

Every method of the `TrustHandlerInterface` takes a `TrustSource` object as input and returns the same object updated with the trust information of a certain entity. This information can be retrieved from the database, if the entity's information was already stored, or reconstructed from the network following the protocol of trustability.

To work correctly the TrustHandler must implements the following methods:

- extract_and_update_trust_materials:
  This method is called internally from the CombinedTrustEvaluator to extract the trust materials from the entity and update the TrustSource object when the trust information of the entity is not stored in the database or outdated. This method must:

  1. Retrieve the trust materials following the protocol of trustability.
  2. Update the TrustSource object with the trust information of the entity using the provided methods like `add_key` to store a public key or `add_trust_param` to store a trust parameter.
  3. Return the updated TrustSource object.
- build_metadata_endpoints:
  Expose one or more metadata endpoints required to publish metadata information about the entity, such as public keys, configurations, and policies. These endpoints are attached to a backend named according to the first function argument.

  The method returns a list of tuples, each containing:

  1. A regex for routing to the endpoint, where the first path must match the backend.
  2. An HTTP handler that provides a response based on the context.

  The `entity_uri` is the full path component of the exposed module, which can also serve as the issuer value when signing tokens. The module is exposed to the web in the pattern `<scheme>://<host>/<base_path>`.

  The TrustHandler may not have any associated metadata endpoints, in which case an empty list is returned.
- get_metadata:
  This method is called internally from the CombinedTrustEvaluator to retrieve the metadata of the entity. This method must:

  1. Retrieve the metadata of the entity following the protocol of trustability.
  2. Update the TrustSource object with the metadata information of the entity using the provided method `add_metadata` to store the metadata.
  3. Return the updated TrustSource object.

Finally, to properly load the custom TrustHandler, the user must define the module in a block under the trust section of the configuration file. The module must contain the following fields:

- module: The module path of the TrustHandler.
- class: The path to the class name of the TrustHandler.
- config: The configuration parameters of the TrustHandler.
  This field is dynamic and must contain all the parameters required by the TrustHandler to work correctly.

The following is an example of the [TrustHandlerInterface](/pyeudiw/trust/handler/interface.py) configuration:

```yaml
    direct_trust_sd_jwt_vc:
        module: pyeudiw.trust.handler.direct_trust_sd_jwt_vc
        class: DirectTrustSdJwtVc
        config:
            cache_ttl: 0
            httpc_params:
                connection:
                    timeout: 10
                session:
                    timeout: 10
            jwk_endpoint: /.well-known/jwt-vc-issuer
```

### Client ID and Default Client ID

The configuration can also define a client id that is used by default when a method of CombinedTrustEvaluator is called without a client_id parameter.
If the client_id is not defined in the configuration of the handler, in the phase of initialization of the CombinedTrustEvaluator, the client_id is set to default_client_id.
