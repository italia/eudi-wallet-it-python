# Wallet Instance Attestation (WIA)

This module provides schemas and utilities for **Wallet Instance Attestation** (WIA),
used for OAuth 2.0 attestation-based client authentication.

WIA is **not part of the OpenID4VP presentation flow**; it is an independent capability
used by other modules (e.g. OpenID4VCI) that require WIA validation or production.

## Schemas

- `CNFSchema` – confirmation (JWK) schema
- `WalletInstanceAttestationHeader` / `WalletInstanceAttestationPayload` – WIA JWT
- `WalletInstanceAttestationRequestHeader` / `WalletInstanceAttestationRequestPayload` – WIA request (var+jwt)

## Usage

```python
from pyeudiw.wallet_instance_attestation import (
    WalletInstanceAttestationHeader,
    WalletInstanceAttestationPayload,
    WalletInstanceAttestationRequestHeader,
    WalletInstanceAttestationRequestPayload,
    CNFSchema,
)
```
