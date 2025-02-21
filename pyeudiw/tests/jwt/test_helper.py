from pyeudiw.jwt.helper import validate_jwt_timestamps_claims
from pyeudiw.tools.utils import iat_now


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
