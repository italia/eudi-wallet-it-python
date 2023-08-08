import pytest
from pydantic import ValidationError

from pyeudiw.openid4vp.schemas.vp_token import VPTokenHeader, VPTokenPayload

VP_TOKEN = {
    "header": {
        "alg": "ES256",
        "typ": "JWT",
        "kid": "e0bbf2f1-8c3a-4eab-a8ac-2e8f34db8a47"
    },
    "payload": {
        "iss": "https://wallet-provider.example.org/instance/vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c",
        "jti": "3978344f-8596-4c3a-a978-8fcaba3903c5",
        "aud": "https://verifier.example.org/callback",
        "iat": 1541493724,
        "exp": 1573029723,
        "nonce": "2c128e4d-fc91-4cd3-86b8-18bdea0988cb",
        "vp": "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkc0UlAyQnhBNW50VUtYNGVhclR0cEo3TUJ1RWwyRzBueFRPU0h4X05POVUiLCAiZTJIa20tLUM3c1ZYTnV2UG5tVFptRnFKNDIxUDR0eWRBTUhfTDRvaWNjVSIsICJ2VWNWSFp5Q0thdXN2X003TGdXa1NqRzRXSUJQaWV1S09HOUE3TjJ2ZUpjIl0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY5MDk1NTUzNSwgImV4cCI6IDE2OTA5NTY0MzUsICJzdWIiOiAiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.YvGqqjp3NjFlOIz6furIKHDYzZibhZPj36vtwgH7fTbgSshCvvvzfTOcwtNA0K3M9wZw7v0BQWdlkLx3SkUJfg~WyI2NFE3OXJKdWkyOVJxWWdHdGpTQ0dBIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ~WyJjR1ctZl9NVmlJUnp6M0Q1QVNxOUt3IiwgImVtYWlsIiwgIm1heEBob21lLmNvbSJd~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIyZjlkZWE4YTBkYmY1ZGRiN2NlOWQyZmRlOWZiOGJkNiIsICJhdWQiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS92ZXJpZmllciIsICJpYXQiOiAxNjkwOTYyNzM1fQ.ScCgejwnR7fdF2trKDSJooNKWiz6-dLQGlQzRK-NVMSayKWXxj6Ebxwleb2MS_SbSHYHN2GygLw5NNyXV_3TlA"
        # "vp": "<SD-JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>"
    }
}


def test_vp_token_header():
    VPTokenHeader(**VP_TOKEN['header'])
    # alg is ES256
    # it should fail if alg is not in supported_algorithms
    with pytest.raises(ValidationError):
        VPTokenHeader.model_validate(
            VP_TOKEN['header'], context={"supported_algorithms": None})
    with pytest.raises(ValidationError):
        VPTokenHeader.model_validate(
            VP_TOKEN['header'], context={"supported_algorithms": []})
    with pytest.raises(ValidationError):
        VPTokenHeader.model_validate(
            VP_TOKEN['header'], context={"supported_algorithms": ["asd"]})

    VPTokenHeader.model_validate(
        VP_TOKEN['header'], context={"supported_algorithms": ["ES256"]})


def test_vp_token_payload():
    VPTokenPayload(**VP_TOKEN['payload'])
    # it should fail on SD-JWT format or missing vp
    VP_TOKEN["payload"]["vp"] = VP_TOKEN["payload"]["vp"].replace("~", ".")
    with pytest.raises(ValidationError):
        VPTokenPayload(**VP_TOKEN['payload'])
    VP_TOKEN["payload"]["vp"] = VP_TOKEN["payload"]["vp"].replace(".", "~")
    del VP_TOKEN["payload"]["vp"]
    with pytest.raises(ValidationError):
        VPTokenPayload(**VP_TOKEN['payload'])
