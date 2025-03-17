import datetime
from pyeudiw.trust.handler.x509 import X509Hanlder
from pyeudiw.tests.x509.test_x509 import gen_chain
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.trust.handler.exceptions import InvalidTrustHandlerConfiguration

def test_wrong_configuration_must_fail():
    try:
        X509Hanlder(
            "https://test.com",
            None,
            []
        )
        assert False, "Should have raised InvalidTrustHandlerConfiguration"
    except InvalidTrustHandlerConfiguration as e:
        assert str(e) == "No x509 certificate chains provided in the configuration"

    try:
        X509Hanlder(
            "https://test.com",
            {
                "example.com": gen_chain(ca_cn="wrong_example.com", ca_dns="wrong_example.com")
            },
            []
        )
        assert False, "Should have raised InvalidTrustHandlerConfiguration"
    except InvalidTrustHandlerConfiguration as e:
        assert str(e) == "Invalid x509 certificate: expected example.com got wrong_example.com"


def test_extract_trust_material_from_x509_handler():
    trust_handler = X509Hanlder(
        "https://example.com",
        {
            "ca.example.com": gen_chain(leaf_cn="example.com", leaf_dns="example.com", leaf_uri="https://example.com")
        },
        [
            {
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
            }
        ]
    )
    trust_source = TrustSourceData.empty("https://example.com")

    trust_handler.extract_and_update_trust_materials("https://example.com", trust_source)
    serialized_object = trust_source.serialize()

    assert "x509" in serialized_object
    assert "x5c" in serialized_object["x509"]
    assert len(serialized_object["x509"]["x5c"]) == 3
    assert "expiration_date" in serialized_object["x509"]
    assert serialized_object["x509"]["expiration_date"] > datetime.datetime.now()
    assert "jwks" in serialized_object["x509"]
    assert serialized_object["x509"]["jwks"][0]["kty"] == "RSA"
    assert "n" in serialized_object["x509"]["jwks"][0]

def test_return_nothing_if_chain_is_invalid():
    trust_handler = X509Hanlder(
        "https://example.com",
        {
            "ca.example.com": gen_chain(leaf_cn="example.com", date=datetime.datetime.fromisoformat("1990-01-01"))
        },
        []
    )
    trust_source = TrustSourceData.empty("https://example.com")

    trust_handler.extract_and_update_trust_materials("https://example.com", trust_source)
    serialized_object = trust_source.serialize()

    assert "x509" not in serialized_object