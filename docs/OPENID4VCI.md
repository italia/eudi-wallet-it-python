# openid4vci — OpenID for Verifiable Credential Issuance

The `pyeudiw.openid4vci` module provides classes and schemas related to [OpenID for Verifiable Credential Issuance](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html).

## Installation

```bash
pip install pyeudiw
# Or with SATOSA frontend:
pip install pyeudiw[satosa]
```

## Overview

The `openid4vci` package contains:

- **Schemas and models** for Credential Offers, Credential Requests, and Credential Responses
- **Credential formats** (SD-JWT VC, mso_mdoc)
- **OAuth 2.0 / OIDC** integration (PAR, PKCE, DPoP, Attestation)

## SATOSA Frontend Integration

The main integration is through the **SATOSA OpenID4VCI frontend**. See [OPENID4VCI-SATOSA-FRONTEND.md](OPENID4VCI-SATOSA-FRONTEND.md) for:

- Frontend configuration
- Credential offer (by value and QR code)
- Credential issuance endpoints
- Trust and storage setup

## Related Documentation

- [OPENID4VCI-SATOSA-FRONTEND.md](OPENID4VCI-SATOSA-FRONTEND.md) — Full SATOSA frontend setup
- [SD-JWT.md](SD-JWT.md) — SD-JWT VC issuance and verification
- [TRUST.md](TRUST.md) — Trust evaluation configuration
- [TOOLS-QRCODE.md](TOOLS-QRCODE.md) — QR code configuration for credential offers
