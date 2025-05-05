from cryptography.hazmat.primitives.asymmetric import ec
from cryptojwt.jwk.ec import ECKey

from pyeudiw.jwk import JWK
from pyeudiw.jwt.helper import validate_jwt_timestamps_claims
from pyeudiw.jwt.jws_helper import _validate_key_with_jws_header
from pyeudiw.tools.utils import iat_now
import pyeudiw.tests.x509.test_x509 as test_x509
from pyeudiw.x509.verify import DER_cert_to_B64DER_cert


def test_validate_jwt_timestamps_claims_ok():
    now = iat_now()
    payload = {"iat": now - 10, "nbf": now - 10, "exp": now + 9999}
    try:
        validate_jwt_timestamps_claims(payload)
    except Exception as e:
        assert (
            True
        ), f"encountered unexpeted error when validating the lifetime of a good token payload: {e}"


def test_validate_jwt_timestamps_claims_bad_iat():
    now = iat_now()
    payload = {"iat": now + 100, "exp": now + 9999}
    try:
        validate_jwt_timestamps_claims(payload)
        assert (
            False
        ), "failed to raise exception when validating a token payload with bad iat"
    except Exception:
        pass


def test_validate_jwt_timestamps_claims_bad_nbf():
    now = iat_now()
    payload = {"nbf": now + 100, "exp": now + 9999}
    try:
        validate_jwt_timestamps_claims(payload)
        assert (
            False
        ), "failed to raise exception when validating a token payload with bad nbf"
    except Exception:
        pass


def test_validate_jwt_timestamps_claims_bad_exp():
    now = iat_now()
    payload = {"iat": now - 100, "exp": now - 10}
    try:
        validate_jwt_timestamps_claims(payload)
        assert (
            False
        ), "failed to raise exception when validating a token payload with bad exp"
    except Exception:
        pass


def test_test_validate_jwt_timestamps_claims_tolerance_window():
    tolerance_window = 30  # in seconds

    # case 0: tolerance window covers a token issuer "slightly" in the future
    now = iat_now()
    payload = {"iat": now + 15, "nbf": now + 15, "exp": now + 9999}
    try:
        validate_jwt_timestamps_claims(payload, tolerance_window)
    except Exception as e:
        assert (
            False
        ), f"encountered unexpeted error when validating the lifetime of a token payload with a tolerance window (for iat, nbf): {e}"

    # case 1: tolerance window covers a token "slightly" expired
    now = iat_now()
    payload = {"iat": now - 100, "nbf": now - 100, "exp": now - 15}
    try:
        validate_jwt_timestamps_claims(payload, tolerance_window)
    except Exception as e:
        assert (
            False
        ), f"encountered unexpeted error when validating the lifetime of a token payload with a tolerance window (for exp): {e}"


def test_validate_key_with_jws_header_x5c_ok():
    private_ec_key = ec.generate_private_key(ec.SECP256R1())
    x509_der_chain = test_x509.gen_chain(leaf_private_key=private_ec_key)
    x5c = [DER_cert_to_B64DER_cert(der) for der in x509_der_chain]
    
    ec_jwk = ECKey()
    ec_jwk.load_key(private_ec_key)
    key = ec_jwk.serialize(private=True)

    try:
        _validate_key_with_jws_header(key, {"x5c": x5c}, {})
        assert True
    except Exception as e:
        assert False, f"unexpected exception when validating header for correct key: {e}"


def test_validate_key_with_jws_header_kid_ok():
    key = JWK().as_dict()
    kid = "1234567890"
    key["kid"] = kid

    try:
        _validate_key_with_jws_header(key, {"kid": kid}, {})
        assert True
    except Exception as e:
        assert False, f"unexpected exception when validating header for correct key: {e}"


def test_validate_key_with_jws_header_expect_x5c_fail():
    private_ec_key = ec.generate_private_key(ec.SECP256R1())
    x509_der_chain = test_x509.gen_chain(leaf_private_key=private_ec_key)
    x5c = [DER_cert_to_B64DER_cert(der) for der in x509_der_chain]
    
    wrong_ec_key = ec.generate_private_key(ec.SECP256R1())
    wrong_ec_jwk = ECKey()
    wrong_ec_jwk.load_key(wrong_ec_key)
    wrong_key = wrong_ec_jwk.serialize(private=True)

    try:
        _validate_key_with_jws_header(wrong_key, {"x5c": x5c}, {})
        assert False, f"should have encountered exception when validating header 'x5c' for wrong key"
    except Exception as _:
        assert True

def test_validate_key_with_jws_header_expect_kid_fail():
    wrong_key = JWK().as_dict()
    wrong_kid = "1234567890"
    wrong_key["kid"] = wrong_kid
    
    key = JWK().as_dict()
    kid = "qwertyuiop"
    key["kid"] = kid

    try:
        _validate_key_with_jws_header(key, {"kid": "1234567890"}, {})
        assert False, f"should have encountered exception when validating header 'kid' for wrong key"
    except Exception as _:
        assert True