# JWK — JSON Web Key

The `pyeudiw.jwk` module provides JSON Web Key (JWK) handling according to [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).

## Installation

```bash
pip install pyeudiw
```

## Creating a JWK Instance

### Generate a new key

```python
from pyeudiw.jwk import JWK

# Default: EC key with P-256 curve
private_key = JWK()
print(private_key.public_key)  # Public key for sharing

# RSA key
rsa_key = JWK(key_type="RSA")

# EC key with specific curve (e.g. P-384)
ec_key = JWK(key_type="EC", ec_crv="P-384")
```

### Load from existing key dict

```python
from pyeudiw.jwk import JWK

key_dict = {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "...",
    "d": "..."  # optional, for private key
}
jwk = JWK(key=key_dict)
```

## Exporting Keys

```python
from pyeudiw.jwk import JWK

key = JWK()

# As JSON string
json_str = key.as_json()

# As dict (includes private part if present)
key_dict = key.as_dict()

# Public key only (no private material)
public_dict = key.as_public_dict()

# PEM format
private_pem = key.export_private_pem()
public_pem = key.export_public_pem()
```

## Parsing Keys from Certificates and PEM

```python
from pyeudiw.jwk import JWK
from pyeudiw.jwk.parse import parse_pem, parse_certificate, parse_b64der, parse_x5c_keys

# From PEM string (public RSA or EC key)
jwk = parse_pem("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----")

# From x509 certificate (PEM or DER)
jwk = parse_certificate(cert_pem_string)
jwk = parse_certificate(cert_der_bytes)

# From Base64-encoded DER certificate
jwk = parse_b64der(base64_der_string)

# From x5c chain (first element = verifying key)
# See RFC 7517 § 4.7
x5c = ["base64der1", "base64der2", ...]
jwks = parse_x5c_keys(x5c)
verifying_key = jwks[0]
```

## Finding Keys in a JWKS

```python
from pyeudiw.jwk.jwks import find_jwk_by_kid, find_jwk_by_thumbprint

jwks = [
    {"kty": "EC", "crv": "P-256", "kid": "key-1", ...},
    {"kty": "EC", "crv": "P-256", "kid": "key-2", ...},
]

# By key ID
jwk_dict = find_jwk_by_kid(jwks, "key-1", as_dict=True)
jwk_obj = find_jwk_by_kid(jwks, "key-1", as_dict=False)

# By thumbprint (for keys without kid, e.g. from certificate chains)
thumbprint = b"..."
found = find_jwk_by_thumbprint(jwks, thumbprint)
```

## Complete Example: Create Key and Build x5c-like Chain

```python
from pyeudiw.jwk import JWK
from pyeudiw.jwk.parse import parse_x5c_keys

# Create a wallet key
wallet_key = JWK()

# Simulate receiving an x5c from a credential
x5c_chain = ["base64_cert_1", "base64_cert_2"]
issuer_keys = parse_x5c_keys(x5c_chain)

# First key in chain verifies the leaf
verification_key = issuer_keys[0]
```
