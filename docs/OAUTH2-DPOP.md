# oauth2.dpop — DPoP (Demonstrating Proof-of-Possession)

The `pyeudiw.oauth2.dpop` module provides tools for issuing and parsing DPoP artifacts according to [OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop).

## Installation

```bash
pip install pyeudiw
```

## Issuing a DPoP Proof

```python
from pyeudiw.jwk import JWK
from pyeudiw.oauth2.dpop.issuer import DPoPIssuer

# Create or load a private key
private_jwk = JWK()
private_dict = private_jwk.as_dict()

# DPoP for a token endpoint request
htu = "https://authorization-server.example.com/token"
dpop_issuer = DPoPIssuer(
    htu=htu,
    private_jwk=private_dict,
    token=None  # No access token yet for token request
)

proof = dpop_issuer.proof
print(proof)  # JWT to send in DPoP header
```

## Issuing a DPoP Proof Bound to an Access Token

When calling a protected resource, bind the DPoP proof to the access token:

```python
from pyeudiw.oauth2.dpop.issuer import DPoPIssuer

htu = "https://resource-server.example.com/api"
access_token = "eyJ..."  # The Bearer token

dpop_issuer = DPoPIssuer(
    htu=htu,
    private_jwk=private_dict,
    token=access_token
)

proof = dpop_issuer.proof
# Use: Authorization: DPoP <proof>
# And: DPoP <proof>
```

## Verifying a DPoP Proof

```python
from pyeudiw.oauth2.dpop.verifier import DPoPVerifier

# Raw header value (with or without "DPoP " prefix)
http_header_dpop = "eyJhbGc..."  # or "DPoP eyJhbGc..."
http_header_authz = "DPoP eyJhbGc..."  # Optional: access token for ath validation

verifier = DPoPVerifier(
    http_header_dpop=http_header_dpop,
    http_header_authz=http_header_authz
)

if verifier.validate():
    print("DPoP valid")
else:
    print("DPoP invalid")
```

## Complete Example: Client-Side Flow

```python
from pyeudiw.jwk import JWK
from pyeudiw.oauth2.dpop.issuer import DPoPIssuer
from pyeudiw.oauth2.dpop.verifier import DPoPVerifier

# 1. Generate DPoP key (client does this once per session)
dpop_key = JWK()
private_jwk = dpop_key.as_dict()

# 2. Request token
htu = "https://as.example.com/token"
dpop = DPoPIssuer(htu=htu, private_jwk=private_jwk)
proof = dpop.proof

# 3. Call token endpoint
# POST .../token
# DPoP: <proof>
# ...

# 4. Later: call protected resource with token binding
access_token = "..."  # from token response
htu_resource = "https://api.example.com/protected"
dpop_bound = DPoPIssuer(
    htu=htu_resource,
    private_jwk=private_jwk,
    token=access_token
)
bound_proof = dpop_bound.proof

# 5. Server verifies
verifier = DPoPVerifier(
    http_header_dpop=bound_proof,
    http_header_authz=access_token
)
assert verifier.validate()
```

## Exceptions

| Exception | When raised |
|-----------|-------------|
| `InvalidDPoP` | General DPoP validation failure |
| `InvalidDPoPKid` | Key ID mismatch |
| `InvalidDPoPAth` | Access token hash mismatch |
