# JWT — Signed and Encrypted JSON Web Tokens

The `pyeudiw.jwt` module provides JWT signing, verification, and encryption according to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515), and [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516).

## Installation

```bash
pip install pyeudiw
```

## Signing a JWT (JWS)

```python
from pyeudiw.jwk import JWK
from pyeudiw.jwt.jws_helper import JWSHelper

# Create a key
private_key = JWK()

payload = {
    "aud": "https://credential-issuer.example.com",
    "iat": 1701960444,
    "nonce": "LarRGSbmUPYtRYO6BQ4yn8"
}

jwt_helper = JWSHelper(private_key)
jws = jwt_helper.sign(
    payload,
    protected={
        "jwk": private_key.public_key,
        "typ": "openid4vci-proof+jwt"
    }
)

print(jws)  # Compact JWS string
```

## Verifying a JWT

```python
from pyeudiw.jwt.jws_helper import JWSHelper

# With a single key or JWKS
jwt_helper = JWSHelper(jwks=[public_jwk_dict])

# Returns the decoded payload on success
payload = jwt_helper.verify(jws)
print(payload)
```

## Signing with JWKS (multiple keys)

```python
from pyeudiw.jwt.jws_helper import JWSHelper

jwks = [private_key_1.as_dict(), private_key_2.as_dict()]
helper = JWSHelper(jwks=jwks)

# Sign with a specific key by kid
jws = helper.sign(payload, signing_kid="my-key-id")

# Or let the helper select based on header
jws = helper.sign(payload, protected={"kid": "my-key-id"})
```

## Decoding Without Verification

```python
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload

header = decode_jwt_header(jwt_string)
payload = decode_jwt_payload(jwt_string)
```

## Encrypting a JWT (JWE)

```python
from pyeudiw.jwt.jwe_helper import JWEHelper

# Encrypt with recipient's public key
jwe_helper = JWEHelper(public_jwk)
jwe = jwe_helper.encrypt(payload, protected={"alg": "RSA-OAEP", "enc": "A256GCM"})
```

## Decrypting a JWE

```python
from pyeudiw.jwt.jwe_helper import JWEHelper

jwe_helper = JWEHelper(private_jwk)
payload = jwe_helper.decrypt(jwe)
```

## Parsing x5c-Based Verification

When the JWT header contains `x5c`, the verifier can use the certificate chain to obtain the verification key:

```python
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwk.parse import parse_x5c_keys

# If token has x5c in header
header = decode_jwt_header(jws)
x5c = header.get("x5c", [])
if x5c:
    keys = parse_x5c_keys(x5c)
    verifier = JWSHelper(jwks=[keys[0].as_dict()])
    payload = verifier.verify(jws)
```

## Utility Functions

```python
from pyeudiw.jwt.helper import is_jwt_expired, is_payload_expired, validate_jwt_timestamps_claims

# Check expiration
is_expired = is_jwt_expired(jwt_string)

# Validate timestamps (iat, exp, nbf) with optional tolerance
validate_jwt_timestamps_claims(payload, tolerance_s=60)
```
