issuer = "https://credential-issuer.example/vct/"
issuer_jwk = {
    "kty": "EC",
    "kid": "MGaAh57cQghnevfWusalp0lNFXTzz2kHnkzO9wOjHq4",
    "crv": "P-256",
    "x": "S57KP4yGauTJJuNvO-wgWr2h_BYsatYUA1xW8Nae8i4", 
    "y": "66DmArglfyJODHAzZsIiPTY24gK70eeXPbpT4Nk0768"
}
issuer_vct_md = {
    "issuer": issuer,
    "jwks": {
        "keys": [
            issuer_jwk
        ]
    }
}