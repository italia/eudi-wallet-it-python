import json
import pytest
import satosa.context

from cryptojwt.jwk.rsa import new_rsa_key
from pyeudiw.jwt.jwe_helper import JWEHelper
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.openid4vp.authorization_response import (
    DirectPostJwtJweParser,
    DirectPostParser,
    normalize_jsonstring_to_string,
)
from pyeudiw.openid4vp.exceptions import (
    AuthRespParsingException,
    AuthRespValidationException,
)
from pyeudiw.tests.settings import CONFIG


@pytest.fixture
def jwe_helper():
    private_key = new_rsa_key()
    jwe_helper = JWEHelper(private_key)
    return jwe_helper

@pytest.fixture
def jws_helper():
    private_key = new_rsa_key()
    jws_helper = JWSHelper(private_key)
    return jws_helper

def test_direct_post_parser_good_case():
    parser = DirectPostParser()

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }
    # case 0: vp_token is string
    ctx.request = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": json.dumps(presentation_submission),
    }

    resp = parser.parse_and_validate(ctx)
    assert resp.vp_token == vp_token
    assert resp.state == state
    assert resp.presentation_submission == presentation_submission

    # case 1: vp_token is a json string
    ctx.request = {
        "vp_token": f'"{vp_token}"',
        "state": state,
        "presentation_submission": presentation_submission
    }

    resp = parser.parse_and_validate(ctx)
    assert resp.vp_token == vp_token
    assert resp.state == state
    assert resp.presentation_submission == presentation_submission


def test_direct_post_response_bad_parse_case():
    # case 0: bad method
    parser = DirectPostParser()

    ctx = satosa.context.Context()
    ctx.request_method = "GET"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }
    ctx.qs_params = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": json.dumps(presentation_submission),
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted a GET request when only POST can be accepted"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"

    # case 1: bad shape
    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    ctx.request = {
        "bad_param_name": "bad parameter value",
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with invalid parameters"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"


def test_direct_post_jwt_jwe_parser_good_case(jwe_helper, jws_helper):

    parser = DirectPostJwtJweParser(
        jwe_helper, 
        jws_helper,
        CONFIG["jwt"].get("enc_alg_supported", []), 
        CONFIG["jwt"].get("enc_enc_supported", [])
    )

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }

    data = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission,
    }
    ctx.request = {"response": jwe_helper.encrypt(data)}

    resp = parser.parse_and_validate(ctx)
    assert resp.vp_token == vp_token
    assert resp.state == state
    assert resp.presentation_submission == presentation_submission


def test_direct_post_jwt_jwe_parser_bad_parse_case(jwe_helper, jws_helper):
    # case 0: bad method
    parser = DirectPostJwtJweParser(
        jwe_helper,
        jws_helper,
        CONFIG["jwt"].get("enc_alg_supported", []), 
        CONFIG["jwt"].get("enc_enc_supported", [])
    )

    ctx = satosa.context.Context()
    ctx.request_method = "GET"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }
    ctx.qs_params = {
        "response": jwe_helper.encrypt(
            {
                "vp_token": vp_token,
                "state": state,
                "presentation_submission": presentation_submission,
            }
        )
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted a GET request when only POST can be accepted"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"

    # case 1: bad shape
    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    ctx.request = {
        "response": jwe_helper.encrypt({"bad_param_name": "bad parameter value"}),
    }

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with invalid parameters"
    except AuthRespParsingException:
        assert True
    except AuthRespValidationException as e:
        assert False, f"obtained unexpected validation exception: {e}"


def test_direct_post_jwt_jwe_parser_bad_validation_case(jwe_helper, jws_helper):
    parser = DirectPostJwtJweParser(
        jwe_helper, 
        jws_helper,
        CONFIG["jwt"].get("enc_alg_supported", []), 
        CONFIG["jwt"].get("enc_enc_supported", []))

    wrong_public_key = {
        "kid": "ybmSufrnl3Cu6OrNcsOF_g95g5zShf2aKpg59PMcMm8",
        "e": "AQAB",
        "kty": "RSA",
        "n": "sCLDmvDKr4y7EHLf4TbjNqa3_p4GnTLqPXdvi0ce2BW2NIK1vYtz9uk8oIlResIWJk1T59LAS8YGF5BLkjLLSyMjrhHySoyRDrBEk_cz-F3Mabc7x-5GDAbxvFDZKQ2n5UVQUWgboFISGp2zpmrYzvewv2WCxZ4a3mS6kwAvjl_S9kahD-SFjiNyHsSaA0lDrF5xQpT2MaMha0dPwgNrChCcG4TTG5YBy4zgktlfA9GRnrEKUJioiKYapMAotziNRBoH128CJGAdMxaO5SVYC0PVLnmKd3cv4bPqGYMRszI6x3i5YUTLk8HwWPL9SUV25pAFp_nDRlgQTdvxssClhZ8VbMZQ3x2I738ixGud_1ggBVFTGDDGDQem4jOz6AsPBVrwtwWStVpA5V5FyEhbgZmE7Orb0cNsmIBjVIPBuFtLBmSELAiJ_WK7ajo3xKtIMTFB-JVX1PVawZOkUzS94BnJ0i7RGc4uzZBhhiOWxBHQGIFhfJnD1OggXnHkVYRn",
        "use": "enc",
    }
    wrong_helper = JWEHelper(wrong_public_key)

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }
    data = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission,
    }
    ctx.request = {"response": wrong_helper.encrypt(data)}

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with wrong encryption"
    except AuthRespParsingException as e:
        assert False, f"obtained unexpected parsing exception: {e}"
    except AuthRespValidationException:
        assert True


def test_normalize_json_string():
    s = 'asd'
    assert s == normalize_jsonstring_to_string(s)
    assert s == normalize_jsonstring_to_string(f'"{s}"')

    sl = ['asd', 'fgh']
    assert sl == normalize_jsonstring_to_string(sl)
    assert sl == normalize_jsonstring_to_string([f'"{sl[0]}"', f'"{sl[1]}"'])

def test_direct_post_jwt_jws_parser_good_case(jwe_helper, jws_helper):
    parser = DirectPostJwtJweParser(
        jwe_helper, 
        jws_helper,
        CONFIG["jwt"].get("enc_alg_supported", []), 
        CONFIG["jwt"].get("enc_enc_supported", [])
    )

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }

    data = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission,
    }
    ctx.request = {"response": jws_helper.sign(data)}

    resp = parser.parse_and_validate(ctx)
    assert resp.vp_token == vp_token
    assert resp.state == state
    assert resp.presentation_submission == presentation_submission

def test_direct_post_jwt_jws_parser_bad_parse_case(jwe_helper, jws_helper):
    parser = DirectPostJwtJweParser(
        jwe_helper, 
        jws_helper,
        CONFIG["jwt"].get("enc_alg_supported", []), 
        CONFIG["jwt"].get("enc_enc_supported", []))

    wrong_public_key = new_rsa_key()
    wrong_helper = JWSHelper(wrong_public_key)

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }
    data = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission,
    }
    ctx.request = {"response": wrong_helper.sign(data)}

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with wrong encryption"
    except AuthRespParsingException as e:
        assert True
    except Exception as e:
        assert False, f"obtained unexpected parsing exception: {e}"

def test_direct_post_jwt_jws_parser_bad_validation_case(jwe_helper, jws_helper):
    parser = DirectPostJwtJweParser(
        jwe_helper, 
        jws_helper,
        CONFIG["jwt"].get("enc_alg_supported", []), 
        CONFIG["jwt"].get("enc_enc_supported", []))

    ctx = satosa.context.Context()
    ctx.request_method = "POST"
    vp_token = "qwe.rty.uio~asd.fgh.jkl"
    state = "123456"
    presentation_submission = {
        "id": "submit-id",
        "definition_id": "definition-id",
        "descriptor_map": [
            {"id": "verifiable-credential-type", "format": "dc+sd-jwt", "path": "$.vct"}
        ],
    }
    data = {
        "vp_token": vp_token,
        "state": state,
        "presentation_submission": presentation_submission,
    }
    ctx.request = {"response": jws_helper.sign(data)[:-1]}  # tamper with the signature

    try:
        parser.parse_and_validate(ctx)
        assert False, "accepted an direct post with wrong encryption"
    except AuthRespParsingException as e:
        assert True
    except Exception as e:
        assert False, f"obtained unexpected parsing exception: {e}"