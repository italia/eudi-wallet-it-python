import base64

from pyeudiw.tools.mso_mdoc import from_jwk_to_mso_mdoc_private_key


def test_from_jwk_to_mso_mdoc_private_key():
    jwk_key = {
        "kty": "EC",
        "d": "i0HQiqDPXf-MqC776ztbgOCI9-eARhcUczqJ-7_httc",
        "use": "sig",
        "crv": "P-256",
        "kid": "SQgNjv4yU8sfuafJ2DPWq2tnOlK1JSibd3V5KqYRhOk",
        "x": "Q46FDkhMjewZIP9qP8ZKZIP-ZEemctvjxeP0l3vWHMI",
        "y": "IT7lsGxdJewmonk9l1_TAVYx_nixydTtI1Sbn0LkfEA",
        "alg": "ES256"
    }
    mso_mdoc_key = from_jwk_to_mso_mdoc_private_key(jwk_key)
    assert mso_mdoc_key["KTY"] == "EC2"
    assert mso_mdoc_key["CURVE"] == "P_256"
    assert mso_mdoc_key["ALG"] ==  jwk_key["alg"]
    assert mso_mdoc_key["KID"] == jwk_key["kid"]
    assert mso_mdoc_key["D"] == b'\x8bA\xd0\x8a\xa0\xcf]\xff\x8c\xa8.\xfb\xeb;[\x80\xe0\x88\xf7\xe7\x80F\x17\x14s:\x89\xfb\xbf\xe1\xb6\xd7'