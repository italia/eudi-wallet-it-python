# Supporting a credential data format

Built-in wire formats today are `dc+sd-jwt` and `mso_mdoc`.

There are two different tasks:

1. **New credential type** on an existing format (new `vct` / `doctype`): mostly YAML.
2. **New wire format**: implement issuance and/or presentation code, then wire it in config.

## New credential type (existing format)

### Issuer (OpenID4VCI)

1. Add an entry under `config.metadata.openid_credential_issuer.credential_configurations_supported` with `format` set to `dc+sd-jwt` or `mso_mdoc`, plus `vct` (SD-JWT) or `doctype` (mdoc).
2. Add a matching key under `config.credential_configurations.credential_specification` with `expiry_days` and a `template` for claim placeholders.
3. Map user attributes in `internal_attributes.yaml` so the credential endpoint can fill the template.

See [OPENID4VCI-SATOSA-FRONTEND.md](OPENID4VCI-SATOSA-FRONTEND.md).

### Verifier (OpenID4VP)

1. Extend `config.dcql_query` with a credential whose `format` is already registered and whose `meta` / `claims` match the type you accept.
2. Keep the corresponding entry in `config.credential_presentation_handlers.formats` (already present for built-in formats).

See [OPENID4VP-SATOSA-BACKEND.md](OPENID4VP-SATOSA-BACKEND.md).

## New wire format

### Presentation (pluggable)

Implement `BaseVPParser` (`pyeudiw.credential_presentation.base_vp_parser`):

```python
from pyeudiw.credential_presentation.base_vp_parser import BaseVPParser

class MyFormatParser(BaseVPParser):
    def parse(self, token: str) -> dict:
        """Return disclosed claims as a flat/nested dict."""
        ...

    def validate(
        self,
        token: str,
        verifier_id: str,
        verifier_nonce: str,
        response_uri: str | None = None,
        jwk_thumbprint: bytes | None = None,
    ) -> None:
        """Raise on invalid signature, expiry, revocation, or audience binding."""
        ...
```

Reference implementations:

- `pyeudiw.satosa.backends.openid4vp.vp_sd_jwt_vc.VpVcSdJwtParserVerifier`
- `pyeudiw.satosa.backends.openid4vp.vp_mdoc_cbor.VpMDocCbor`

Register it in the OpenID4VP backend YAML:

```yaml
credential_presentation_handlers:
  max_submission_size: 4096
  formats:
    - module: mypackage.my_format
      class: MyFormatParser
      format: my+format
```

Also declare the format in `config.metadata.vp_formats` and in `config.dcql_query` credentials that use it.

### Issuance (not pluggable yet)

Issuance dispatches on format inside `BaseCredentialEndpoint._build_credential` (`pyeudiw.satosa.frontends.openid4vci.endpoints.base_credential_endpoint`). Supported values live in `CredentialConfigurationFormatEnum` (`pyeudiw.satosa.schemas.metadata`).

To add a format you currently need to:

1. Add the format string to `CredentialConfigurationFormatEnum` and any format-specific field checks on `CredentialConfiguration`.
2. Implement an `_issue_<format>(...)` helper that builds the credential bytes/string from the user entity, template, holder key, and status list.
3. Extend the `match config.format` branch in `_build_credential` (and template loading in `_loader` if the format needs its own rendering).
4. Publish the format in `credential_configurations_supported` and add a `credential_specification` template as above.

Until issuance is refactored to load format handlers like presentation does, a custom format is a library change, not config alone.

## Checklist

| Layer | What to touch |
| ----- | ------------- |
| Issuer metadata | `credential_configurations_supported.<id>.format` |
| Issuer templates | `credential_configurations.credential_specification` |
| Issuer code (new format only) | `CredentialConfigurationFormatEnum`, `_build_credential`, issuer helper |
| Verifier DCQL | `dcql_query.credentials[].format` |
| Verifier parsers | `credential_presentation_handlers.formats` + `BaseVPParser` subclass |
| Verifier metadata | `metadata.vp_formats` |
