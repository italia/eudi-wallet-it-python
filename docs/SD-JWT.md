# SD-JWT Documentation

## Introduction
This document explains how to create and verify a Self-Contained JWT (SD-JWT) using the EUDI Wallet IT Python library. It also covers how to validate proof of possession.

## Creating an SD-JWT

### Step 1: Import Necessary Modules
To get started, you need to import the necessary modules from the EUDI Wallet IT Python library.

```python
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt.exceptions import UnknownCurveNistName
from pyeudiw.sd_jwt.verifier import SDJWTVerifier
from json import dumps, loads
```

### Step 2: Prepare User Claims
Define the claims that you want to include in your SD-JWT.

```python
user_claims = {
    "iss": "issuer_identifier",  # The identifier for the issuer
    "sub": "subject_identifier",  # The identifier for the subject
    "exp": 1234567890,            # Expiration time (in seconds)
    "iat": 1234567890,            # Issued at time (in seconds)
    # Add other claims as needed
}
```

### Step 3: Create Keys
Generate or load your JSON Web Keys (JWKs).

```python
issuer_key = JWK(key_type='RSA')  # Example for RSA key
holder_key = JWK(key_type='RSA')   # Example for RSA key
```

### Step 4: Issue SD-JWT
Create an instance of `SDJWTIssuer` and generate the JWT.

```python
sd_jwt_issuer = SDJWTIssuer(
    user_claims=user_claims,
    issuer_key=issuer_key,
    holder_key=holder_key,
    sign_alg='RS256',  # Example signing algorithm
)

sd_jwt = sd_jwt_issuer.serialize()  # Get the serialized SD-JWT
print("Serialized SD-JWT:", sd_jwt)
```

## Verifying an SD-JWT

### Step 1: Prepare the JWT
Receive the SD-JWT that you want to verify.

```python
received_sd_jwt = sd_jwt  # The JWT you want to verify
```

### Step 2: Create Verifier Instance
Use the `SDJWTVerifier` to verify the JWT.

```python
sd_jwt_verifier = SDJWTVerifier(
    received_sd_jwt,
    issuer_key=issuer_key,
    holder_key=holder_key,
)

verified_claims = sd_jwt_verifier.verify()  # Get the verified claims
print("Verified Claims:", verified_claims)
```

## Proof of Possession

To verify proof of possession, ensure that the holder key matches the expected public key during verification. This process should be included in your verification logic.

```python
if holder_key.verify(verified_claims):
    print("Proof of possession is valid.")
else:
    print("Invalid proof of possession.")
```  

  

**Note:** 
For more specific implementation details read more on [SD-JWT](../pyeudiw/sd_jwt/SD-JWT.md).