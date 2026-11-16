import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptojwt.jwk.ec import ECKey

import pyeudiw.tests.x509.test_x509 as test_x509
from pyeudiw.jwk.exceptions import KidNotFoundError
from pyeudiw.jwk.parse import parse_certificate
from pyeudiw.jwt.exceptions import JWSVerificationError
from pyeudiw.jwt.jws_helper import DEFAULT_TOKEN_TIME_TOLERANCE, JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header
from pyeudiw.tools.utils import iat_now
from pyeudiw.x509.verify import DER_cert_to_B64DER_cert


class TestJWSHeperSelectSigningKey:
    @pytest.fixture
    def sign_jwks(self):
        return [
            {
                "crv": "P-256",
                "d": "qIVMRJ0ioosFjCFhBw-kLBuip9tV0Y2D6iYD42nCKBA",
                "kid": "ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI",
                "kty": "EC",
                "use": "sig",
                "x": "_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40",
                "y": "CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk",
            },
            {
                "crv": "P-256",
                "d": "SW976Rpuse5crOTbM5yBifa7u1tgw46XlJCJRwon4kA",
                "kid": "35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas",
                "kty": "EC",
                "use": "sig",
                "x": "RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk",
                "y": "xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M",
            },
        ]

    def test_JWSHelper_select_signing_key_undefined(self, sign_jwks):
        signer = JWSHelper(sign_jwks)
        try:
            signer._select_signing_key(())
            assert False, "unable to select signing key when no header is given"
        except Exception:
            pass

    def test_JWSHelper_select_signing_key_forced(self, sign_jwks):
        signer = JWSHelper(sign_jwks)
        exp_k = sign_jwks[0]
        k = signer._select_signing_key(({}, {}), signing_kid=exp_k["kid"])
        assert k == exp_k

    def test_JWSHelper_select_signing_key_infer_kid(self, sign_jwks):
        signer = JWSHelper(sign_jwks)
        exp_k = sign_jwks[1]
        k = signer._select_signing_key(({"kid": exp_k["kid"]}, {}))
        assert k == exp_k

    def test_JWSHelper_select_signing_key_infer_kid_x5c(self, sign_jwks: list[dict]):
        new_private_ec_key = ec.generate_private_key(ec.SECP256R1())
        x509_der_chain = test_x509.gen_chain(leaf_private_key=new_private_ec_key)
        x5c = [DER_cert_to_B64DER_cert(der) for der in x509_der_chain]
        new_ec_jwk = ECKey()
        new_ec_jwk.load_key(new_private_ec_key)
        exp_key: dict = new_ec_jwk.serialize(private=True)
        sign_jwks.append(exp_key)

        signer = JWSHelper(sign_jwks)
        obt_key = signer._select_signing_key(({"x5c": x5c}, {}))
        assert exp_key == obt_key

    def test_JWSHelper_select_signing_key_unique(self, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        exp_k = sign_jwks[0]
        k = signer._select_signing_key(({}, {}))
        assert k == exp_k


class TestJWSHelperSignerHeader:
    @pytest.fixture
    def sign_jwks(self):
        return [
            {
                "crv": "P-256",
                "d": "qIVMRJ0ioosFjCFhBw-kLBuip9tV0Y2D6iYD42nCKBA",
                "kid": "ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI",
                "kty": "EC",
                "use": "sig",
                "x": "_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40",
                "y": "CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk",
            },
            {
                "crv": "P-256",
                "d": "SW976Rpuse5crOTbM5yBifa7u1tgw46XlJCJRwon4kA",
                "kid": "35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas",
                "kty": "EC",
                "use": "sig",
                "x": "RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk",
                "y": "xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M",
            },
        ]

    def test_signed_header_add_kid(self, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        jws = signer.sign("", protected={}, kid_in_header=True)
        dec_header = decode_jwt_header(jws)
        assert "kid" in dec_header
        assert sign_jwks[0]["kid"] == dec_header["kid"]

    def test_signed_header_no_add_kid(self, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        jws = signer.sign("", protected={}, kid_in_header=False)
        dec_header = decode_jwt_header(jws)
        assert not ("kid" in dec_header)

    def test_signed_header_add_alg(selg, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        jws = signer.sign("", protected={}, kid_in_header=False)
        dec_header = decode_jwt_header(jws)
        assert "alg" in dec_header


class TestJWSHelperSelectVerifyingKey:
    @pytest.fixture
    def verify_jwks(self):
        return [
            {
                "crv": "P-256",
                "kid": "ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI",
                "kty": "EC",
                "use": "sig",
                "x": "_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40",
                "y": "CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk",
            },
            {
                "crv": "P-256",
                "kid": "35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas",
                "kty": "EC",
                "use": "sig",
                "x": "RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk",
                "y": "xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M",
            },
        ]

    def test_JWSHelper_select_verifying_key_undefined(self, verify_jwks):
        verifier = JWSHelper(verify_jwks)
        k = verifier._select_verifying_key({})
        assert k is None

    def test_JWSHelper_select_verifying_key_kid(self, verify_jwks):
        verifier = JWSHelper(verify_jwks)
        exp_k = verify_jwks[1]
        k = verifier._select_verifying_key({"kid": exp_k["kid"]})
        assert k == exp_k

    def test_JWSHelper_select_verifying_key_unique(self, verify_jwks):
        exp_k = verify_jwks[1]
        verifier = JWSHelper(exp_k)
        k = verifier._select_verifying_key({})
        assert k == exp_k


class TestJWSHelperSignVerify:
    @pytest.fixture
    def signing_key(self):
        return {
            "crv": "P-256",
            "d": "1Fpynl9yQN88xI_AIkna0PiO0-5y5vUtNwC7rbg-BHE",
            "kid": "lfnXwtreAr8zgUE9CUFr9rGZsS5f52I7whhfiPr5I1o",
            "kty": "EC",
            "use": "sig",
            "x": "2I-JeMD_JgNw95NORslAFUElmwMHWbT4uOdDCy99mac",
            "y": "Oy7Cyg2O_4GsLt475BbD5m71-snr52uMneUUHRiodBY",
        }

    def test_JWSHelper_sign_then_verify(self, signing_key):
        helper = JWSHelper(signing_key)
        claims = {
            "iat": iat_now(),
            "exp": iat_now() + 999,
            "iss": "token-issuer",
            "sub": "token-subject",
            "aud": "token-audience",
        }
        token = helper.sign(claims, kid_in_header=True)
        assert "alg" in decode_jwt_header(token)
        assert "kid" in decode_jwt_header(token)

        observed_claims = helper.verify(token)
        # check that library did not include any extra claim when not required
        assert claims == observed_claims, "verified claims do not match signed claims"

    @pytest.fixture
    def x5c_token_and_key(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        chain = test_x509.gen_chain(leaf_private_key=private_key)
        key = ECKey()
        key.load_key(private_key)
        key.kid = "issuer-defined-kid"
        token = JWSHelper(key.serialize(private=True)).sign(
            {"sub": "credential"},
            protected={"x5c": [DER_cert_to_B64DER_cert(cert) for cert in chain[:-1]]},
        )
        return token, parse_certificate(chain[0]).as_public_dict()

    def test_verify_x5c_with_issuer_defined_kid(self, x5c_token_and_key):
        token, trusted_key = x5c_token_and_key
        assert trusted_key["kid"] != decode_jwt_header(token)["kid"]
        unrelated_key = parse_certificate(test_x509.gen_chain()[0]).as_public_dict()
        verifier = JWSHelper([unrelated_key, trusted_key])
        assert verifier.verify(token) == {"sub": "credential"}
        assert verifier.jwks[1].kid == trusted_key["kid"]

    def test_verify_x5c_rejects_untrusted_key(self, x5c_token_and_key):
        token, _ = x5c_token_and_key
        unrelated_key = parse_certificate(test_x509.gen_chain()[0]).as_public_dict()
        with pytest.raises(KidNotFoundError):
            JWSHelper(unrelated_key).verify(token)

    def test_verify_x5c_rejects_mismatched_explicit_trusted_kid(self, x5c_token_and_key):
        token, trusted_key = x5c_token_and_key
        trusted_key["kid"] = "different-explicit-kid"
        with pytest.raises(KidNotFoundError):
            JWSHelper(trusted_key).verify(token)

    def test_verify_unknown_kid_without_x5c_is_rejected(self, signing_key):
        token = JWSHelper(signing_key).sign({"sub": "credential"})
        trusted_key = {**signing_key, "kid": "different-kid"}
        with pytest.raises(KidNotFoundError):
            JWSHelper(trusted_key).verify(token)

    def test_verify_x5c_rejects_invalid_signature(self, x5c_token_and_key):
        token, trusted_key = x5c_token_and_key
        header, _, signature = token.split(".")
        modified_token = f"{header}.eyJzdWIiOiJtb2RpZmllZCJ9.{signature}"
        with pytest.raises(JWSVerificationError):
            JWSHelper(trusted_key).verify(modified_token)

    def test_JWSHelper_sign_then_verify_clock_skewed(self, signing_key):
        helper = JWSHelper(signing_key)

        # case 0: forced tolerance
        claims = {
            "iat": iat_now() + 15,  # oops, issuer clock is slightly skewed!
            "exp": iat_now() + 999,
            "iss": "token-issuer",
            "sub": "token-subject",
            "aud": "token-audience",
        }
        token = helper.sign(claims, kid_in_header=True)

        try:
            helper.verify(token, tolerance_s=60)
        except Exception as e:
            assert False, f"unexpected verification error: {e}"

        # case 1: using global configured tolerance
        DEFAULT_TOKEN_TIME_TOLERANCE
        claims = {
            "iat": iat_now()
            + DEFAULT_TOKEN_TIME_TOLERANCE
            // 2,  # oops, issuer clock is slightly skewed!
            "exp": iat_now() + 999,
            "iss": "token-issuer",
            "sub": "token-subject",
            "aud": "token-audience",
        }
        try:
            helper.verify(token)
        except Exception as e:
            assert False, f"unexpected verification error: {e}"
