# JWT Signature and Verification

````
from pyeudiw.jwt import JWK, JWSHelper

private_key = JWK()

payload = {
    "aud": "https://credential-issuer.example.com",
    "iat": 1701960444,
    "nonce": "LarRGSbmUPYtRYO6BQ4yn8"
}

jwt = JWSHelper(private_key)
jws = jwt.sign(
    payload, 
    protected={
        "jwk":private_key.public_key, 
        "typ": "openid4vci-proof+jwt"
    }
)

# it returns the payload
jwt.verify(jws)
````
