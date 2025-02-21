import json

import requests


def _generate_response(issuer: str, issuer_jwk: dict) -> requests.Response:
    issuer_vct_md = {"issuer": issuer, "jwks": {"keys": [issuer_jwk]}}

    jwt_vc_issuer_endpoint_response = requests.Response()
    jwt_vc_issuer_endpoint_response.status_code = 200
    jwt_vc_issuer_endpoint_response.headers.update({"Content-Type": "application/json"})
    jwt_vc_issuer_endpoint_response._content = json.dumps(issuer_vct_md).encode("utf-8")

    return jwt_vc_issuer_endpoint_response


def _generate_empty_json_ok_response() -> requests.Response:
    resp = requests.Response()
    resp.status_code = 200
    resp.headers.update({"Content-Type": "application/json"})
    resp._content = json.dumps({}).encode("utf-8")
    return resp


issuer = "https://credential-issuer.example/vct/"
issuer_jwk = {
    "kty": "EC",
    "kid": "MGaAh57cQghnevfWusalp0lNFXTzz2kHnkzO9wOjHq4",
    "crv": "P-256",
    "x": "S57KP4yGauTJJuNvO-wgWr2h_BYsatYUA1xW8Nae8i4",
    "y": "66DmArglfyJODHAzZsIiPTY24gK70eeXPbpT4Nk0768",
}
issuer_vct_md = {"issuer": issuer, "jwks": {"keys": [issuer_jwk]}}
jwt_vc_issuer_endpoint_response = requests.Response()
jwt_vc_issuer_endpoint_response.status_code = 200
jwt_vc_issuer_endpoint_response.headers.update({"Content-Type": "application/json"})
jwt_vc_issuer_endpoint_response._content = json.dumps(issuer_vct_md).encode("utf-8")
