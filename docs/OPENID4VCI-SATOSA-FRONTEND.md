# SATOSA frontend setup

To install the OpenID4VCI SATOSA frontend you just need to:

1. install this package and the extra dependencies: `pip install pyeudiw[satosa]`
2. copy and customize [openid4vci_frontend.yaml](pyeudiw_integration_test/conf/openid4vci_frontend.yaml)
3. include the fronted configuration in your satosa configuration
4. customize the file `internal_attributes.yaml` used in your deployment, enabling the `openid4ci` protocol.
   See [internal_attributes.yaml](pyeudiw_integration_test/conf/internal_attributes.yaml) as example.
5. start Satosa.

## Frontend configuration

1. Customize [openid4vci_frontend.yaml](pyeudiw_integration_test/conf/openid4vci_frontend.yaml), then copy it in your
   satosa `plugins/frontend` project folder. Example `plugins/frontend/openid4vci_frontend.yaml`;
2. Add `  - "plugins/frontend/openid4vci_frontend.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section
   `FRONTEND_MODULES`;
3. Customize [internal_attributes.yaml](pyeudiw_integration_test/conf/internal_attributes.yaml), then copy it the path
   your have configured in your `proxy_conf.yaml` file.

### Frontend Configuration Parameters

#### Top-Level

| Parameter | Description                                         | Example value                                                     |
|-----------|-----------------------------------------------------|-------------------------------------------------------------------|
| module    | The name of the module that implements the frontend | pyeudiw.satosa.frontends.openid4vci.openid4vci.OpenID4VCIFrontend |
| name      | The name of the frontend                            | OpenID4VCI                                                        |

#### Config

##### Endpoints

| Parameter                                | Description                                                                                                                               |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| config.endpoints.par                     | The endpoint for the pushed authorization request to get a `request_uri` used in later authorization flows.                               |
| config.endpoints.credential_offer        | The endpoint that initiating the issuance flow by informing wallet about available credentials.                                           |
| config.endpoints.credential_offer_qrcode | The endpoint that initiating the issuance flow by informing wallet about available credentials with qrcode scanner.                       |
| config.endpoints.authorization           | The endpoint with standard OAuth 2.0 where the user authenticates and authorizes the issuance of credentials.                             |
| config.endpoints.token                   | The endpoint for issues access tokens to the Wallet after successful authorization.                                                       |
| config.endpoints.nonce                   | The endpoint that provides a one-time-use nonce to the wallet, used to generate a proof of possession.                                    |
| config.endpoints.credential              | The endpoint where the wallet sends a request to receive one or more verifiable credentials.                                              |
| config.endpoints.metadata                | The endpoint that provides configuration metadata about the issuer, including supported credential formats, proof, methods and endpoints. |
| config.endpoints.status_list             | The endpoint that serves status list that allow Wallets or Verifiers to check the current status of issued credentials.                   |

Each endpoint value is structured according to the format described above, for example:

```
    par:
      module: pyeudiw.satosa.frontends.openid4vci.endpoints.pushed_authorization_request_endpoint
      class: ParHandler
      path: '/par'
```

- module: as python module path
- class: as endpoint handler class that contains `endpoint` method
- path: as path to expose

This structure is mandatory to dynamically expose the endpoints.

The listed endpoints are the ones currently implemented. By properly configuring the yaml endpoint configuration
section, it's possible to override them or add new ones.

### QR Code Configuration

| Key                               | Description                                                                                              | Example Value                      |
|-----------------------------------|----------------------------------------------------------------------------------------------------------|------------------------------------|
| `size`                            | Size of the QR code in pixels                                                                            | `250`                              |
| `color`                           | Hex color code for the QR code                                                                           | `"#000000"`                        |
| `expiration_time`                 | Expiration time of the QR code in seconds                                                                | `120`                              |
| `logo_path`                       | Relative path to the logo image, used in the center of the QR code (relative to `static_storage_url`)    | `"wallet-it/wallet-icon-blue.svg"` |
| `ui.static_storage_url`           | Base URL or path for serving static assets (e.g., CSS, JS, images). Can be set via environment variable. | `!ENV SATOSA_BASE_STATIC`          |
| `ui.template_folder`              | Path to the folder containing HTML templates, relative to the project root.                              | `templates`                        |
| `ui.qrcode_template`              | Filename of the HTML template used to render a QR code page.                                             | `qr_code.html`                     |
| `ui.authorization_error_template` | Filename of the HTML template shown when an authorization error occurs.                                  | `authorization_error.html`         |

##### JWT

| Parameter                    | Description                                                                                                        | Example value                                                                     |
|------------------------------|--------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| config.jwt.default_sig_alg   | The default signature algorithm for the JWT                                                                        | ES256                                                                             |
| config.jwt.default_enc_alg   | The default encryption algorithm for the JWT                                                                       | RSA-OAEP                                                                          |
| config.jwt.default_enc_enc   | The default encryption encoding for the JWT                                                                        | A256CBC-HS512                                                                     |
| config.jwt.default_exp       | The default expiration time for the JWT in minutes                                                                 | 6                                                                                 |
| config.jwt.enc_alg_supported | The list of supported encryption algorithms for the JWT                                                            | [RSA-OAEP, RSA-OAEP-256, ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW] |
| config.jwt.enc_enc_supported | The list of supported encryption encodings for the JWT                                                             | [A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM]          |
| config.jwt.sig_alg_supported | The list of supported signature algorithms for the JWT                                                             | [RS256, RS384, RS512, ES256, ES384, ES512]                                        |
| config.jwt.access_token_exp  | The default and mandatory expiration time, in minutes, for the JWT access token returned by the `token` endpoint.  | 90                                                                                |
| config.jwt.refresh_token_exp | The default and mandatory expiration time, in minutes, for the JWT refresh token returned by the `token` endpoint. | 120                                                                               |
| config.jwt.par_exp           | The default and mandatory expiration time, in minutes, for the JWT token returned by the `par` endpoint.           | 90                                                                                |

##### Network

| Parameter                                   | Description                                                     | Example Value |
|---------------------------------------------|-----------------------------------------------------------------|---------------|
| config.network.httpc_params.connection.ssl  | The flag to indicate whether to use SSL for the HTTP connection | true          |
| config.network.httpc_params.session.timeout | The timeout value for the HTTP session                          | 6             |

##### Trust

| Parameter    | Description                                                                                                         |
|--------------|---------------------------------------------------------------------------------------------------------------------|
| config.trust | A dictionary of trust implementation, where the key is a user friendly identitfier and the value is described below |

The parameters of a `config.trust` dictionary entry value are

| Parameter                          | Description                                                 | Example Value                                |
|------------------------------------|-------------------------------------------------------------|----------------------------------------------|
| config.trust.`<identifier>`.module | A python module that provides a trust implementation        | pyeudiw.trust.default.direct_trust_sd_jwt_vc |
| config.trust.`<identifier>`.class  | The class in the module that implements the trust interface | DirectTrustSdJwtVc                           |
| config.trust.`<identifier>`.config | The configuration of the class in the module                |                                              |

For more deatils on available trust implementations and their configurations, see [docs/TRUST.md](/docs/TRUST.md)

##### Metadata jwks

| Parameter            | Description                                          | Example Value |
|----------------------|------------------------------------------------------|---------------|
| config.metadata_jwks | The list of (private) JSON Web Keys for the metadata |               |

##### Storage

| Parameter                                                                         | Description                                            | Example Value                 |
|-----------------------------------------------------------------------------------|--------------------------------------------------------|-------------------------------|
| config.storage.mongo_db.cache.module                                              | The module name for the MongoDB cache                  | pyeudiw.storage.mongo_cache   |
| config.storage.mongo_db.cache.class                                               | The class name for the MongoDB cache                   | MongoCache                    |
| config.storage.mongo_db.cache.init_params.url                                     | The URL for the MongoDB connection                     | mongodb://satosa-mongo:27017  |
| config.storage.mongo_db.cache.init_params.conf.db_name                            | The database name for the MongoDB cache                | eudiw                         |
| config.storage.mongo_db.cache.connection_params.username                          | The username for authentication to the database        | satosa                        |
| config.storage.mongo_db.cache.connection_params.password                          | The password for authentication to the database        | thatpassword                  |
| config.storage.mongo_db.storage.module                                            | The python module that implements the storage class    | pyeudiw.storage.mongo_storage |
| config.storage.mongo_db.storage.class                                             | The name of the storage class                          | MongoStorage                  |
| config.storage.mongo_db.storage.init_params.url                                   | The URL of the mongodb server                          | mongodb://satosa-mongo:27017  |
| config.storage.mongo_db.storage.init_params.conf.db_name                          | The name of the database to use for storage            | eudiw                         |
| config.storage.mongo_db.storage.init_params.conf.db_sessions_collection           | The name of the collection to store sessions           | sessions                      |
| config.storage.mongo_db.storage.init_params.conf.db_trust_attestations_collection | The name of the collection to store trust attestations | trust_attestations            |
| config.storage.mongo_db.storage.init_params.conf.db_trust_anchors_collection      | The name of the collection to store trust anchors      | trust_anchors                 |
| config.storage.mongo_db.storage.init_params.conf.data_ttl                         | The lifetime duration of data in the database          | 63072000                      |
| config.storage.mongo_db.storage.connection_params.username                        | The username for authentication to the database        | satosa                        |
| config.storage.mongo_db.storage.connection_params.password                        | The password for authentication to the database        | thatpassword                  |

##### User Storage

Configuration for retrieving user data. Typically implemented using MongoDB, it stores user attributes required to
generate the requested credential with `credential` endpoint.

| Parameter                                                                    | Description                                         | Example Value                |
|------------------------------------------------------------------------------|-----------------------------------------------------|------------------------------|
| config.user_storage.mongo_db.storage.module                                  | The python module that implements the storage class | pyeudiw.storage.user_storage |
| config.user_storage.mongo_db.storage.class                                   | The name of the storage class                       | UserStorage                  |
| config.user_storage.mongo_db.storage.init_params.url                         | The URL of the mongodb server                       | mongodb://satosa-mongo:27017 |
| config.user_storage.mongo_db.storage.init_params.conf.db_name                | The name of the database to use for storage         | eid_user                     |
| config.user_storage.mongo_db.storage.init_params.conf.db_sessions_collection | The name of the collection to store users           | users                        |
| config.user_storage.mongo_db.storage.init_params.conf.data_ttl               | The lifetime duration of data in the database       | 63072000                     |
| config.user_storage.mongo_db.storage.connection_params.username              | The username for authentication to the database     | satosa                       |
| config.user_storage.mongo_db.storage.connection_params.password              | The password for authentication to the database     | thatpassword                 |

###### MongoDB Document Example for a User

```json
{
  "_id": ObjectId,
  "name": "Mario",
  "surname": "Rossi",
  "fiscal_code": "RSSMRA80A01H501T",
  "dateOfBirth": "1980-01-01",
  "placeOfBirth": "Roma",
  "countyOfBirth": "IT",
  "mail": "mario.rossi@example.com",
  "portrait": null
}
```

| Field           | Type           | Description                                 |
|-----------------|----------------|---------------------------------------------|
| `name`          | string         | User’s given name.                          |
| `surname`       | string         | User’s family name / last name.             |
| `dateOfBirth`   | string         | Date of birth in ISO format (YYYY-MM-DD).   |
| `fiscal_code`   | string         | Unique fiscal code (Italian tax code).      |
| `countyOfBirth` | string         | Country code (ISO 3166-1 alpha-2) of birth. |
| `placeOfBirth`  | string         | City or locality where the user was born.   |
| `portrait`      | string or null | Base64-encoded image (optional).            |
| `mail`          | string         | User’s email address.                       |

These fields must be present as keys in the `internal_attributes.yaml` file to enable matching and dynamic value
population in the credential templates defined in `config.credential_configurations.credential_specification` used by
the `credential` endpoint.

##### Credential Storage

Configuration for retrieving credentials data. Typically implemented using MongoDB, it's a storage system used by both
the `credential` and `status_list` endpoints. It maintains the state of each credential in relation to the corresponding
user, supporting status updates such as issuance and revocation.

| Parameter                                                                          | Description                                         | Example Value                      |
|------------------------------------------------------------------------------------|-----------------------------------------------------|------------------------------------|
| config.credential_storage.mongo_db.storage.module                                  | The python module that implements the storage class | pyeudiw.storage.credential_storage |
| config.credential_storage.mongo_db.storage.class                                   | The name of the storage class                       | CredentialStorage                  |
| config.credential_storage.mongo_db.storage.init_params.url                         | The URL of the mongodb server                       | mongodb://satosa-mongo:27017       |
| config.credential_storage.mongo_db.storage.init_params.conf.db_name                | The name of the database to use for storage         | eid_credential                     |
| config.credential_storage.mongo_db.storage.init_params.conf.db_sessions_collection | The name of the collection to store credentials     | credentials                        |
| config.credential_storage.mongo_db.storage.init_params.conf.data_ttl               | The lifetime duration of data in the database       | 63072000                           |
| config.credential_storage.mongo_db.storage.connection_params.username              | The username for authentication to the database     | satosa                             |
| config.credential_storage.mongo_db.storage.connection_params.password              | The password for authentication to the database     | thatpassword                       |

###### MongoDB Document Example for a Credential

```json
{
  "_id": ObjectId,
  "user_id": user.ObjectId,
  "incremental_id": 1,
  "revoked": false,
  "identifier": "dc_sd_jwt_mDL:abc123"
}
```

| Field            | Type     | Description                                                                                        |
|------------------|----------|----------------------------------------------------------------------------------------------------|
| `user_id`        | `string` | A foreign key referencing the user (e.g., `user._id`). It links the credential to a specific user. |
| `incremental_id` | `int`    | A sequential identifier for the credential, useful for tracking or versioning.                     |
| `revoked`        | `bool`   | Indicates whether the credential has been revoked (`true`) or is still valid (`false`).            |
| `identifier`     | `string` | A unique identifier for the credential.                                                            |

##### Metadata

The main metadata paths will be listed below, including those required for the workflows of the various endpoints.
These metadata will be exposed through the `metadata` endpoint.

###### OAuth Authorization Server

Configuration of the OAuth Authorization Server metadata.

| YAML Path                                                                        | Description                                                                          |
|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| config.metadata.oauth_authorization_server.issuer                                | Issuer URL of the authorization server (autopopulated if omitted)                    |
| config.metadata.oauth_authorization_server.pushed_authorization_request_endpoint | PAR (Pushed Authorization Request) endpoint path                                     |
| config.metadata.oauth_authorization_server.authorization_endpoint                | Authorization endpoint path                                                          |
| config.metadata.oauth_authorization_server.token_endpoint                        | Token endpoint path                                                                  |
| config.metadata.oauth_authorization_server.client_registration_types_supported   | Supported client registration types                                                  |
| config.metadata.oauth_authorization_server.acr_values_supported                  | Supported ACR (Authentication Context Class Reference) values                        |
| config.metadata.oauth_authorization_server.scopes_supported                      | List of supported OAuth2 scopes. Mandatory for `par` and `token` endpoints.          |
| config.metadata.oauth_authorization_server.response_modes_supported              | Supported response modes (e.g., query, form_post.jwt). Mandatory for `par` endpoint. |
| config.metadata.oauth_authorization_server.response_types_supported              | OAuth2 response types supported. Mandatory for `par` endpoint.                       |
| config.metadata.oauth_authorization_server.grant_types_supported                 | Supported grant types (e.g., authorization_code)                                     |
| config.metadata.oauth_authorization_server.token_endpoint_auth_methods_supported | Token endpoint authentication methods                                                |
| config.metadata.oauth_authorization_server.jwks                                  | JWKS used for signing/verifying messages                                             |
| config.metadata.oauth_authorization_server.code_challenge_methods_supported      | Supported PKCE methods. Mandatory for `par` endpoint.                                |

###### OpenId Credential Issuer

OpenID4VCI Credential Issuer metadata.

| YAML Path                                                                    | Description                                                                                                           |
|------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| config.metadata.openid_credential_issuer.credential_issuer                   | Credential Issuer identifier URL                                                                                      |
| config.metadata.openid_credential_issuer.credential_endpoint                 | Endpoint for issuing credentials                                                                                      |
| config.metadata.openid_credential_issuer.nonce_endpoint                      | Endpoint to retrieve nonces                                                                                           |
| config.metadata.openid_credential_issuer.deferred_credential_endpoint        | Endpoint to retrieve deferred credentials                                                                             |
| config.metadata.openid_credential_issuer.revocation_endpoint                 | Endpoint for credential revocation                                                                                    |
| config.metadata.openid_credential_issuer.status_assertion_endpoint           | Endpoint to check credential status (status list or assertion)                                                        |
| config.metadata.openid_credential_issuer.notification_endpoint               | Notification callback endpoint                                                                                        |
| config.metadata.openid_credential_issuer.credential_hash_alg_supported       | Supported hash algorithm for credential thumbprint                                                                    |
| config.metadata.openid_credential_issuer.display                             | Multilingual display names for the issuer                                                                             |
| config.metadata.openid_credential_issuer.credential_configurations_supported | Supported credential types and their configurations. Mandatory for `par`, `credential`, `credential offer` endpoints. |
| config.metadata.openid_credential_issuer.trust_frameworks_supported          | List of supported trust frameworks                                                                                    |
| config.metadata.openid_credential_issuer.evidence_supported                  | Supported evidence types (e.g., vouch)                                                                                |
| config.metadata.openid_credential_issuer.jwks                                | JWKS used for signing credentials                                                                                     |

###### Federation Entity

Metadata for OpenID Federation.

| YAML Path                                           | Description                    |
|-----------------------------------------------------|--------------------------------|
| config.metadata.federation_entity.organization_name | Legal name of the organization |
| config.metadata.federation_entity.homepage_uri      | Homepage URL                   |
| config.metadata.federation_entity.policy_uri        | Privacy policy URL             |
| config.metadata.federation_entity.tos_uri           | Terms of service URL           |
| config.metadata.federation_entity.logo_uri          | Logo URL                       |
| config.metadata.federation_entity.contacts          | Contact email addresses        |

##### Credential configurations

Root section for credential management configuration.

| Key                                                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|-----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| config.credential_configurations.lookup_source            | Source used to filter attributes, typically matching a key from `internal_attributes.yaml`. Mandatory in `credential` endpoint.                                                                                                                                                                                                                                                                                                                            |
| config.credential_configurations.status_list.path         | Path to the status list endpoint (used for revocation or suspension of credentials). Mandatory in `status_list` endpoint.                                                                                                                                                                                                                                                                                                                                  |
| config.credential_configurations.status_list.exp          | Expiration time for the status list (in minutes). Mandatory in `status_list` endpoint.                                                                                                                                                                                                                                                                                                                                                                     |
| config.credential_configurations.status_list.ttl          | Time-to-live for the status list (in minutes). Mandatory in `status_list` endpoint.                                                                                                                                                                                                                                                                                                                                                                        |
| config.credential_configurations.credential_specification | A dictionary where each key corresponds to a credential type declared in `config.metadata.openid_credential_issuer.credential_configurations_supported` (metadata). Each value includes the `expiry_days` (validity in days) and a `template` for rendering the credential with placeholders in given format present in `config.metadata.openid_credential_issuer.credential_configurations_supported.<cred>.format`.  Mandatory in `credential` endpoint. |

### Environment Variables for Key Configuration

The following environment variables can be used to configure the `metadata_jwks` and `federation_jwks` dynamically.
These variables accept JSON-formatted strings representing the keys.

| Environment Variable      | Description                                                                                                  | Example Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|---------------------------|--------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PYEUDIW_METADATA_JWKS`   | Contains the private JSON Web Keys (JWK) used for metadata. Each key must be represented as a JSON object.   | `[{"kty":"EC", "crv":"P-256", "x":"TSO-KOqdnUj5SUuasdlRB2VVFSqtJOxuR5GftUTuBdk", "y":"ByWgQt1wGBSnF56jQqLdoO1xKUynMY-BHIDB3eXlR7", "d":"KzQBowMMoPmSZe7G8QsdEWc1IvR2nsgE8qTOYmMcLtc", "use":"sig", "kid":"signing-key-id"}, {"kty":"EC", "crv":"P-256", "x":"TSO-KOqdnUj5SUuasdlRB2VVFSqtJOxuR5GftUTuBdk", "y":"ByWgQt1wGBSnF56jQqLdoO1xKUynMY-BHIDB3eXlR7", "d":"KzQBowMMoPmSZe7G8QsdEWc1IvR2nsgE8qTOYmMcLtc", "use":"enc", "kid":"encryption-key-id"}]`                                                                                                                                                                                                                                                                                                         |
| `PYEUDIW_FEDERATION_JWKS` | Contains the private JSON Web Keys (JWK) used for federation. Each key must be represented as a JSON object. | `[{"kty":"RSA", "n":"utqtxbs-jnK0cPsV7aRkkZKA9t4S-WSZa3nCZtYIKDpgLnR_qcpeF0diJZvKOqXmj2cXaKFUE-8uHKAHo7BL7T-Rj2x3vGESh7SG1pE0thDGlXj4yNsg0qNvCXtk703L2H3i1UXwx6nq1uFxD2EcOE4a6qDYBI16Zl71TUZktJwmOejoHl16CPWqDLGo9GUSk_MmHOV20m4wXWkB4qbvpWVY8H6b2a0rB1B1YPOs5ZLYarSYZgjDEg6DMtZ4NgiwZ-4N1aaLwyO-GLwt9Vf-NBKwoxeRyD3zWE2FXRFBbhKGksMrCGnFDsNl5JTlPja", "e":"AQAB","d":"QUZsh1NqvpueootsdSjFQz-BUvxwd3Qnzm5qNb-WeOsvt3rWMEv0Q8CZrla2tndHTJhwioo1U4NuQey7znijhZ177bUwPPxSW1r68dEnL2U74nKwwoYeeMdEXnUfZSPxzs7nY6b7vtyCoA-AjiVYFOlgKNAItspv1HxeyGCLhLYhKvS_YoTdAeLuegETU5D6K1xGQIuw0nS13Icjz79Y8jC10TX4FdZwdX-NmuIEDP5-s95V9DMENtVqJAVE3L-wO-NdDilyjyOmAbntgsCzYVGH9U3W_djh4t3qVFCv3r0S-DA2FD3THvlrFi655L0QHR3gu_Fbj3b9Ybtajpue_Q", "kid":"private-signing-key-id"}]` |

## Environment Variables Configuration

SATOSA supports the following environment variables to customize its behavior:

| **Variable Name**                | **Description**                                                                                  | **Default Value**   | **Allowed Values**         | **Context**               |
|----------------------------------|--------------------------------------------------------------------------------------------------|---------------------|----------------------------|---------------------------|
| `PYEUDIW_MONGO_TEST_AUTH_INLINE` | MongoDB connection string used for SATOSA integration tests.                                     | `""` (empty string) | Valid MongoDB URI          | Integration Testing       |
| `PYEUDIW_LRU_CACHE_MAXSIZE`      | Configures the maximum number of elements to store in the Least Recently Used (LRU) cache.       | `2048`              | Integer                    | Cache Management          |
| `PYEUDIW_HTTPC_SSL`              | Enables or disables SSL verification for HTTP client requests.                                   | `True`              | `True`, `False`            | HTTP Client Configuration |
| `PYEUDIW_HTTPC_TIMEOUT`          | Sets the timeout for HTTP client requests.                                                       | `6` seconds         | Integer                    | HTTP Client Configuration |
| `PYEUDIW_TOKEN_TIME_TOLERANCE`   | Global default tolerance windows to be used when validating token lifetime claims such as `iat`. | `60` seconds        | Integer                    | Tokens (JWT) validation   |
| `SD_JWT_HEADER`                  | Specifies the type of SD-JWT header to use when generating or verifying SD-JWTs.                 | `dc+sd-jwt`         | Custom values as per usage | SD-JWT Configuration      |

### Notes:

1. These variables are optional and, if not explicitly set, default values will be used.
2. To define these variables, you can use export commands in shell scripts, or any environment variable management tool.
