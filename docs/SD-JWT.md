# sd-jwt-python Fork with cryptojwt

## Introduction

This module is a fork of [sd-jwt-python](https://github.com/openwallet-foundation-labs/sd-jwt-python) project. It has been adapted to use the [`cryptojwt`](https://github.com/IdentityPython/JWTConnect-Python-CryptoJWT) library as the core JWT implementation. 


If you're familiar with the original `sd-jwt-python` library, this fork retains similar functionality with minimal API changes, if needed.

---

## Features

- **SD-JWT Support**: Implements the Selective Disclosure JWT standard.
- **`cryptojwt` Integration**: Leverages a mature and feature-rich library for JWT operations.
- **Backward Compatibility**: Minimal changes required for existing users of `sd-jwt-python`.
- **Improved Flexibility**: Extensible for custom SD-JWT use cases.

---

# SD-JWT Library Usage Documentation

## Introduction

This library provides an implementation of the SD-JWT (Selective Disclosure for JWT) standard. This document explains how to create and verify a Selected-Disclosure JWT (SD-JWT) using the EUDI Wallet IT Python library. It also covers how to validate proof of possession enabling three key operations:
1. **Issuer**: Generate an SD-JWT with selective disclosure capabilities.
2. **Holder**: Select claims to disclose and create a presentation.
3. **Verifier**: Validate the SD-JWT and verify the disclosed claims.

### Requirements
- Python version as configured in the CI of this project.
- Install the library via `pip`:
```bash
pip install pyeudiw
```

- **Key Requirements**:
  - All keys must be in JWK (JSON Web Key) format, conforming to [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
  - You can use a library like `cryptojwt` to generate or manage JWKs. Example:

```bash
from cryptojwt.jwk.ec import new_ec_key

# Generate an EC key pair
issuer_private_key = new_ec_key('P-256')

# Serialize the keys
issuer_keys = [issuer_private_key.serialize(private=True)]  # List of private keys
public_key = issuer_private_key.serialize()  # Public key
```
---

## 1. Issuer: Generating an SD-JWT

The Issuer creates an SD-JWT using the user's claims (`user_claims`) and a private key in JWK format to sign the token.

### Example

```bash
from pyeudiw.sd_jwt.issuer import SDJWTIssuer

# User claims
user_claims = {
    "sub": "john_doe_42",
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
}

# Generate private keys
issuer_private_key = new_ec_key('P-256')
issuer_keys = [issuer_private_key.serialize(private=True)]  # List of private JWKs
holder_key = new_ec_key('P-256').serialize(private=True)    # Holder private key (optional)

# Create SD-JWT
sdjwt_issuer = SDJWTIssuer(
    user_claims=user_claims,
    issuer_keys=issuer_keys,       # List of private JWKs
    holder_key=holder_key,         # Holder key (optional)
    add_decoy_claims=True,         # Add decoy claims for privacy
    serialization_format="compact" # Compact JWS format
)

# Output SD-JWT and disclosures
print("SD-JWT Issuance:", sdjwt_issuer.sd_jwt_issuance)
```

---

## 2. Holder: Creating a Selective Disclosure Presentation

The Holder receives the SD-JWT from the Issuer and selects which claims to disclose to the Verifier.

### Example

```bash
from pyeudiw.sd_jwt.holder import SDJWTHolder

# Claims to disclose
holder_disclosed_claims = {
    "given_name": True,
    "family_name": True
}

# Initialize Holder
sdjwt_holder = SDJWTHolder(sdjwt_issuer.sd_jwt_issuance)

# Create presentation with selected claims
sdjwt_holder.create_presentation(
    disclosed_claims=holder_disclosed_claims,
    nonce=None,             # Optional: Used for key binding
    verifier=None,          # Optional: Verifier identifier for key binding
    holder_key=holder_key   # Optional: Holder private key for key binding
)

# Output the presentation
print("SD-JWT Presentation:", sdjwt_holder.sd_jwt_presentation)
```

## 3. Verifier: Verifying an SD-JWT

The Verifier validates the SD-JWT and checks the disclosed claims.

### Example

```python
from pyeudiw.sd_jwt.verifier import SDJWTVerifier

# Callback to retrieve Issuer's public key
def get_issuer_public_key(issuer, header_parameters):
    # Return the public key(s) in JWK format
    return [issuer_private_key.serialize()]

# Initialize Verifier
sdjwt_verifier = SDJWTVerifier(
    sdjwt_presentation=sdjwt_holder.sd_jwt_presentation,
    cb_get_issuer_key=get_issuer_public_key
)

# Verify and retrieve payload
verified_payload = sdjwt_verifier.get_verified_payload()

# Verified claims
print("Verified Claims:", verified_payload)
```


---

```