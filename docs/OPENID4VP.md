# openid4vp — OpenID for Verifiable Presentations

The `pyeudiw.openid4vp` module provides classes and schemas related to [OpenID for Verifiable Presentations](https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html).

## Installation

```bash
pip install pyeudiw
# Or with SATOSA backend:
pip install pyeudiw[satosa]
```

## Overview

The `openid4vp` package contains:

- **Schemas and models** for Authorization Requests, Presentations, and Response objects
- **DCQL (Duckle)** query language support for credential requests
- **Presentation definitions** and credential format handling

## SATOSA Backend Integration

The main integration is through the **SATOSA OpenID4VP backend**. See [OPENID4VP-SATOSA-BACKEND.md](OPENID4VP-SATOSA-BACKEND.md) for:

- Backend configuration
- Endpoints (pre-request, request, response, status)
- Trust evaluation setup
- QR code and UI settings

## Credential Presentation Handlers

Presentation verification uses `CredentialPresentationHandlers`, which load format-specific parsers (e.g. SD-JWT, mdoc):

```python
from pyeudiw.credential_presentation.handler import load_credential_presentation_handlers
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

# Load from backend config
config = {...}
trust_evaluator = CombinedTrustEvaluator.from_config(...)
handlers = load_credential_presentation_handlers(
    config["credential_presentation_handlers"],
    trust_evaluator,
)
```

## Related Documentation

- [OPENID4VP-SATOSA-BACKEND.md](OPENID4VP-SATOSA-BACKEND.md) — Full SATOSA backend setup
- [TRUST.md](TRUST.md) — Trust evaluation configuration
- [SD-JWT.md](SD-JWT.md) — SD-JWT VC format
