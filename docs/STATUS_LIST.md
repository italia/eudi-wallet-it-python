# status_list — Credential Revocation (Token Status List)

The `pyeudiw.status_list` module provides credential revocation check mechanisms according to [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/).

## Installation

```bash
pip install pyeudiw
```

## Decoding a JWT Status List

```python
from pyeudiw.status_list import decode_jwt_status_list_token

token = "eyJ..."  # statuslist+jwt token

ok, header, payload, bits, status_list = decode_jwt_status_list_token(token)
if ok:
    print("Bits per status:", bits)
    print("Status list (decompressed):", status_list)
```

## Decoding a CWT Status List

```python
from pyeudiw.status_list import decode_cwt_status_list_token

token_hex = "d284..."  # statuslist+cwt as hex bytes

ok, header, payload, bits, status_list = decode_cwt_status_list_token(token_hex)
if ok:
    print("Bits per status:", bits)
```

## Generating a Status List

```python
from pyeudiw.status_list import generate_status_list, array_to_bitstring

# Status array: each item has incremental_id and revoked flag
status_array = [
    {"incremental_id": 1, "revoked": False},
    {"incremental_id": 2, "revoked": True},
    {"incremental_id": 3, "revoked": False},
]

# Convert to bitstring (1 bit per status by default)
bitstring = array_to_bitstring(status_array, bit_size=1)

# Generate JWT-style status list (dict with bits and lst)
status_list_dict = generate_status_list(
    bitstring,
    bits=1,
    aggregation_uri="https://status.example.com/list",
    format="jwt"
)
# status_list_dict: {"bits": 1, "lst": "<base64-compressed>", "aggregation_uri": "..."}

# Or CWT format (bytes)
status_list_cwt = generate_status_list(bitstring, bits=1, format="cwt")
```

## Encoding a CWT Status List (Signed)

```python
from pyeudiw.status_list import encode_cwt_status_list_token

payload_parts = (
    {"alg": "ES256", 16: "application/statuslist+cwt"},  # Protected header
    {},                                                    # Unprotected header
    {"iss": "https://issuer.example.com", "sub": "..."}   # Payload
)
bits = 1
status_list = b"..."
private_key = {"KTY": "EC2", "CURVE": "P_256", "D": b"...", "KID": b"..."}

token_hex = encode_cwt_status_list_token(
    payload_parts,
    bits=bits,
    status_list=status_list,
    private_key=private_key
)
```

## Complete Example: Check Revocation Status

```python
from pyeudiw.status_list import decode_jwt_status_list_token

# Credential has status_list credential in credentialStatus
# status_list.index = 0  -> first credential in list
# status_list.status_list_index = 42 -> bit index 42

token = "..."  # Fetch from status_list.credential_status.status_list_uri
ok, header, payload, bits, status_list_bytes = decode_jwt_status_list_token(token)

if not ok:
    raise ValueError("Invalid status list")

# Interpret bit at index 42
byte_index = 42 // 8
bit_index = 42 % 8
revoked = (status_list_bytes[byte_index] >> (7 - bit_index)) & 1
print("Revoked:", bool(revoked))
```
