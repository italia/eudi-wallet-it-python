from pyeudiw.openid4vp.exceptions import VPSchemaException
from pyeudiw.openid4vp.vp_sd_jwt_kb import VpVcSdJwtKbVerifier


def test_VpVcSdJwtKbVerifier():
    token = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.sMpGS2JtqTtflUN-ToEm2VueqHhVCpUtOXk0SV5Tjj7FulFGae2fIaULLDjdKa46T-wtI9nKMoSNqe_38uwBhg~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3MjA0NTQyOTUsICJzZF9oYXNoIjogIkEyM3lUaG5uN0FidlVlNkE5N1YtTHJsdGFRUTRaMkdIRjJlUXBMUkRCVncifQ.u0CjLD2kenwkwA4vttK7PFhjtEEV5r4dYMR7TW1VAC35xIc1dMkEtvdTRwLQBO1Tu9VcbkvxT-G9ooTTVZMD2g"
    aud = "https://example.com/verifier"
    nonce = "1234567890"
    jwk_d = {
        "doc-signer-05-25-2022": {
            "kid": "doc-signer-05-25-2022",
            "kty": "EC",
            "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
        }
    }
    claims = [
        "address",  # discolsed
        "family_name"  # NOT disclosed
    ]
    verifier = VpVcSdJwtKbVerifier(token, aud, nonce, jwk_d, claims)
    try:
        verifier.validate_schema()
    except VPSchemaException:
        # TODO: example that is actually aligned with italian specs
        pass
    verifier.verify_vp()
    expected_credentials = {"address": {"street_address": "123 Main St", "locality": "Anytown", "region": "Anystate", "country": "US"}}
    credentials = verifier.parse_digital_credential()
    assert credentials == expected_credentials, f"failed to parse credentials: expected {expected_credentials}, obtained {credentials}"
