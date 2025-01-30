import pytest

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header


class TestJWSHeperSelectSigningKey:
    @pytest.fixture
    def sign_jwks(self):
        return [
            {"crv": "P-256", "d": "qIVMRJ0ioosFjCFhBw-kLBuip9tV0Y2D6iYD42nCKBA", "kid": "ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI",
                "kty": "EC", "use": "sig", "x": "_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40", "y": "CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk"},
            {"crv": "P-256", "d": "SW976Rpuse5crOTbM5yBifa7u1tgw46XlJCJRwon4kA", "kid": "35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas",
                "kty": "EC", "use": "sig", "x": "RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk", "y": "xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M"}
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

    def test_JWSHelper_select_signing_key_unique(self, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        exp_k = sign_jwks[0]
        k = signer._select_signing_key(({}, {}))
        assert k == exp_k


class TestJWSHelperSignerHeader():
    @pytest.fixture
    def sign_jwks(self):
        return [
            {"crv": "P-256", "d": "qIVMRJ0ioosFjCFhBw-kLBuip9tV0Y2D6iYD42nCKBA", "kid": "ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI",
                "kty": "EC", "use": "sig", "x": "_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40", "y": "CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk"},
            {"crv": "P-256", "d": "SW976Rpuse5crOTbM5yBifa7u1tgw46XlJCJRwon4kA", "kid": "35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas",
                "kty": "EC", "use": "sig", "x": "RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk", "y": "xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M"}
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


class TestJWSHelperSelectVerifyingKey():
    @pytest.fixture
    def verify_jwks(self):
        return [
            {"crv": "P-256", "kid": "ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI", "kty": "EC", "use": "sig",
                "x": "_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40", "y": "CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk"},
            {"crv": "P-256", "kid": "35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas", "kty": "EC", "use": "sig",
                "x": "RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk", "y": "xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M"}
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
