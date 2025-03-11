import json
from dataclasses import dataclass

import pytest
import satosa.context
import satosa.response

from pyeudiw.jwk import JWK
from pyeudiw.trust.handler.direct_trust_jar import DirectTrustJar


@pytest.fixture
def signing_private_key() -> list[dict]:
    return [
        {
            "crv": "P-256",
            "d": "r8UhwdbIvxKLvObVE-yixibCtu-0nzBZ3QGQ_-i1owc",
            "kid": "MmjIDEhSnyIha4n462iIzrmdwMnJWlRZnsOJ3LWBEC4",
            "kty": "EC",
            "use": "sig",
            "x": "xEmx9ruaf1qycPoYQ5lIfMSXAz2qLib6n0Ar_WDEiHM",
            "y": "ZkSlQyYxuVTEKNRdrnONTisTepQ-3VcCza2O2yejawQ",
        }
    ]

@pytest.fixture
def rsa_signing_private_key() -> list[dict]:
    return [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "123114cf-ebef-48d9-9602-3be85e6e12dd",
        "d": "b41VkvQv083zdtsqX9Q4RqW6DOH7LcSMSSK-KaUi-jtR4SdPkans1vY9QwfZ1gL-iQm0UP50Txow1Xawnh_-O45efpTOJ0sEXno5gXregQQNXxum-ATh7npYTv3Zjfl1lw4GX9UvXwtko3zHA01OtvOdXxtDHtatvoojFEwTisBT5j9f_q7Dmmgmtml17U_M1heANv9O9PqOey2U7_wZRji2lLGpeP7DxeBpTVztyKdnBZCjBnwfyrES3eAPlO5GI3zWAxHuaSsms3F8WQKJqHQs8xDxHpC1MCPMqmnCZnrBxZXxeeg6gMuEJ72RtzziOwH2gr3alND6gpARwwgEYQ",
        "n": "oV1dBQQpxKhVpJzouceEvuJQ_0nIvK3GVF4FEKRunCWK1amBupkegZgIXq98WsvfNHLwKPhhFXO1unONb44Q51VeFet7ThWyJSB9dhXmr21wvqFA4HVQj4vGPLiGUmacKL-9W4vd_ElLyf1TEtcolUafEI83zfg6bsVkJrwdSRDkxYU5Kh28ayCgoaqXUwLsuR-xT5EiksJESHtqW5_8sqrp5v95UOxxK8NdbEQ54Fr2pfeKQ6Id5VyUlwOnfnV6zgJJ7qBM1NxcyQ7OkQHrh03LfoPF2Hl7-EuZ0ET8p9RVC7eC2NH033O9rSiWljwwsvmRG7nyVN7bkB5wbInp0Q",
        "e": "AQAB",
        "p": "0RHnCQZiI6VomMmRcfDyRgqZjUEHLPF17u4TAxqFys3-lgxuRCn8cjXkzJ7t9C0FmGNQy2zrwhQZRUlKotPwB9t0qTRwshqmG40O4EHfdgqu_sqNe8toCJ9xGqkDJFdYvmPy-SkqMYyszRf1GEwMjgj1Ncyx4WciaEbHZUllQo0",
        "q": "xZYanwkJJGOD4b7Z2PwCA_ubEYU8O2C3UoeINv2P5fXicXRK278o4WelaQBhyvDcPyS3lJyyusB_ro3Fax1fm4IDV1buITar671NzooWKOUQgG0MoVHS8k7qFmGXGDhFBrO_khsvc3FNAjdqkNpH5slo8AwvN2SrbHO3GX6aVVU",
        "dp": "tk7iJCCI24SVXQYH6k-tNB5yH5ag5zP3Hs5DjeVG3b4bTkSwsofaNs2AIl5EKTRJOMUB4yGrw6U7FAwBJVOib3eSlym_S8-pIUUzv6IxdgGC73M5RMXuhfZi7liLANmZ7QvDCDo5LNP6qy1E8FcAa6qsCKniQydn_X4aydvijNE",
        "dq": "Ml9mQg1Hq2NDiBXj7BGzYdiPXBQfmvO5SO0MqRhTy0i4hjwjqYo-ndiSrwZN6DMns2Fk_BpG5p2U76dtITXH3hlzSJz88LLDecI1R-akZ6CeaF9kzOvTX7sGqtYOczpFPsQsns8XddL40wvVu0Aq_Id0nV49211q5qdJktJX_lE",
        "qi": "rQ5SbqNeVrGOZ1rJXWbiAxux_-E1HBunOKWN6HQpoStLpRzJ6zz8aEXhSXMAnbeQOi1ZBS1escmlSupkgz4TEnrhionAJ2orIJ1rOiZIii7stJVkB3fs2LBoxs17Msj9AVrBA-tHhWpoBj63t-ahhEuxhgReq_0DjzQgcP7xUA"
    }]

@pytest.fixture
def all_private_keys(signing_private_key: list[dict]) -> list[dict]:
    rsa_pkey = {
        "d": "l2vENvwM3YVZ7C36mDKGJIjaadzhc_3JSuUrj5PUj1DMRfDf5jElrseIg8hyWhi5n6FqN8uV_2hfw-xUarwx_glFtbe0StqVqHLAYpGg7Id8fe5CKUPsjweNBq9zx9EMKNZl5q_tBW4ZnhyLhbmv-tO0NUz2ht2moOOPsqycNymblxs3bIZKTLxwEfx9rBhXkOUJ8MWciRjvaA1kOTY5pT__AnhmEdqCGaqgSxfmf4tyudatREt7mhnOQqIPtyVPFFCHZHsHv5Akp9U7bA2cbke8NarfBlLbZufzj2sSaVErAn-po1KIB3fuA9HBs4YeDGcRv3hipUJrACMqYm5zhODdSr-P6X-3-FR5EWnSDUDwYeWZ7q1jzGzgKAXEbnn-CXY_JlXaYGfRUqIXui883rr9IjqI-c1TVcSPaSVpnxut9rwfkxuQo7MEbiExODGfXNvbR9S8DWJXWjKmFZklResqK6wWFe7GXkDLDeWRtbtRxEYirIkxPgNt3EXcm3sp",
        "e": "AQAB",
        "kid": "KwJFzr11BxhSmAW8D2ZGBDQRdiQXZo1YWGaxHGW5Md8",
        "kty": "RSA",
        "n": "wDBeA9a1xgOEb_zwm05cZnblBJANfWBA7oaZRYLp1sl0030pK6jHyEJ4wrXlMMQcxvwOx80uRFJG3o9BLTQ5lPnBu-VMAxF9LTkLZRD_gAJsrHz_myCgfcCMouX9AwDtUC01p5IIZ8YgfrbYPn694RxhCmH09oGs_OwOr7f3aW2qwf7uha7LRy8UPDYULnST7eqqWgrxjSIeHnmeO9BmEfcvqZJD2EfFHwFVXkjwMk1nWnQZYRV7Yncoz3qV0rhIQ86FQ2i4BoMW54OnRrgRHGqVUBHZP2y_Z3xo6foYOXJMgkHcEasiLbiATvHHN1cVsaM0PvQjO15qZu2IvVK224MgY6YbWU88pssG0ydTSOo0bY5gDhY6ml133MKXzfES0dzLNoOALrkyFxiHrPgQiFMKBuPXZ6qk1RomEWZYR54Brd7gDyK66MkdmpHvgBJf_V1YO42U1yxUTg63shdRp4O8FNZoTmhjMT9A_ZCD5mqGo00IewLHiQzVyWDqNrPv",
        "p": "0P7Vjj2Rc8tGdxqXvg77FsUaJIpoffgHSv59zrctOF7odKRYOSKW9FvlOi01NZE8dkcdYxlnriy3jyQVdGTxbRKJKKHrJbIJpqMDj6wUrk0k-67PbBuAJhzhmU_2wlyd04U7lt8gcn55kyV5XxQta6WTHz11MgO1GKePfCIlTRyS1T26_5wq5a_Q_VcdmiKuBHm0HtkBCkSYTWxWqfQjehs8eR5xOBAasgZHNit1KCMiONeUNyFtVFWgSSjDzhfL",
        "q": "62ngt1zghnj8pguWq1Xx6hRtE-eFS5K0rn6hSCgkLnUQeZWpO7cB4EEHFbN5FlWFIj9bjrRIoTQtHwprtM7dMqVaBH2HcKwSDiZy9ImmW2peKrP7Ko1t-Eg9Mhm8rycuzrwu3iQdd41JH-My5Fti-IuXyhZ3IVF_JvVNQKf4_RZQD4mbslEc6KFjLT-A3V6wfMhVFw7rnR6GcyQ0YUJTjzhRP3siG1A3GYGF1eN0pqT_3Lk2tvkd174BwcifiGft",
        "qi": "TFYkChfG3DRtgOiPRzl_yj_CDrYNsGWM-s0GmRHy_Zl1NvHK9u8Pc4hPoS9xx_qZiBnapX_Jmkaz39Q0GsjsJqjQQRxPMIofh1SZzH6O_tJ1-YQhJO4OfsQwi_FIAoDXHetkxnnhG1Axpvfqx5UyKM18uBz1vfWVrpfqaz9EBT04roVR_RFGzzV9jzDXFaZ17SWvovGtpHKqkVrCU0z6D8FV0lhuyBTmee6jXcxfzkwizGR6VexfaVwAHj7OdDGs",
        "use": "enc",
    }
    return signing_private_key + [rsa_pkey]


@pytest.fixture
def direct_trust_jar(all_private_keys):
    return DirectTrustJar(jwks=all_private_keys)


def test_direct_trust_jar_build_metadata_path(direct_trust_jar):
    @dataclass
    class TestCase:
        backend_name: str
        expected_path: str
        explanation: str

    test_cases: list[TestCase] = [
        TestCase(
            backend_name="",
            expected_path=".well-known/jar-issuer",
            explanation="empty backend name",
        ),
        TestCase(
            backend_name="openid4vp",
            expected_path="openid4vp/.well-known/jar-issuer",
            explanation="regular backend name",
        ),
        TestCase(
            backend_name="/openid4vp/",
            expected_path="openid4vp/.well-known/jar-issuer",
            explanation="backend name with usual slashes",
        ),
    ]

    for i, case in enumerate(test_cases):
        path_component = direct_trust_jar._build_metadata_path(case.backend_name)
        assert (
            path_component == case.expected_path
        ), f"failed case {i+1}: test scenario: {case.explanation}"


def test_direct_trust_jat_custom_path(all_private_keys):
    @dataclass
    class TestCase:
        endpoint_component: str
        backend_name: str
        expected_path: str
        explanation: str

    test_cases: list[TestCase] = [
        TestCase(
            endpoint_component="custom",
            backend_name="openid4vp",
            expected_path="openid4vp/custom",
            explanation="custom path",
        ),
        TestCase(
            endpoint_component="/custom-with-slashes/",
            backend_name="openid4vp",
            expected_path="openid4vp/custom-with-slashes",
            explanation="custom path with prepending and appending forward slash",
        ),
    ]
    for i, case in enumerate(test_cases):
        dtj = DirectTrustJar(
            jwks=all_private_keys, jwk_endpoint=case.endpoint_component
        )
        path_component = dtj._build_metadata_path(case.backend_name)
        assert (
            path_component == case.expected_path
        ), f"failed case {i+1}: test scenario: {case.explanation}"


def test_direct_trust_jar_metadata(direct_trust_jar):
    backend = "openid4vp"
    entity_id = f"https://rp.example/{backend}"
    metadata = direct_trust_jar._build_metadata_with_issuer_jwk(entity_id)
    assert metadata["issuer"] == entity_id
    assert len(metadata["jwks"]["keys"]) == 1
    pub_key = metadata["jwks"]["keys"][0]
    assert "d" not in pub_key
    assert pub_key.get("use", "") != "enc"

def test_direct_trust_jar_metadata_no_private_key(all_private_keys, rsa_signing_private_key):
    dtj = DirectTrustJar(jwks=all_private_keys+rsa_signing_private_key)

    backend = "openid4vp"
    entity_id = f"https://rp.example/{backend}"
    metadata = dtj._build_metadata_with_issuer_jwk(entity_id)
    assert len(metadata["jwks"]["keys"]) == 2

    assert "d" not in metadata["jwks"]["keys"][0]
    assert metadata["jwks"]["keys"][0].get("use", "") != "enc"

    assert "d" not in metadata["jwks"]["keys"][1]
    assert "p" not in metadata["jwks"]["keys"][1]
    assert "q" not in metadata["jwks"]["keys"][1]
    assert "dp" not in metadata["jwks"]["keys"][1]
    assert "dq" not in metadata["jwks"]["keys"][1]
    assert "qi" not in metadata["jwks"]["keys"][1]
    assert metadata["jwks"]["keys"][1].get("use", "") != "enc"


def test_direct_trust_metadata_handler(direct_trust_jar, signing_private_key):
    backend = "openid4vp"
    entity_id = f"https://rp.example/{backend}"
    registered_methods = direct_trust_jar.build_metadata_endpoints(backend, entity_id)
    assert len(registered_methods) == 1

    endpoint_regexp = registered_methods[0][0]
    assert endpoint_regexp == "^openid4vp/.well-known/jar-issuer$"

    http_handler = registered_methods[0][1]
    empty_context = satosa.context.Context()
    response = http_handler(empty_context, "test")
    assert "200" in response.status
    assert response._content_type == "application/json"
    try:
        response.headers.index(("Content-Type", "application/json"))
    except Exception as e:
        assert True, f"unable to find application/json in response content type: {e}"

    response_data = json.loads(response.message)
    assert response_data["issuer"] == entity_id
    assert len(response_data["jwks"]["keys"]) == 1

    pub_key = response_data["jwks"]["keys"][0]
    expected_pub_key = JWK(signing_private_key[0]).as_public_dict()
    assert pub_key == expected_pub_key
