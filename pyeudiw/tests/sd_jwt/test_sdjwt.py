import builtins
from dataclasses import dataclass

from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt.schema import VerifierChallenge
from pyeudiw.sd_jwt.sd_jwt import SdJwt

# DEVELOPER NOTE: test data is collected from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-12.html
# Test data might eventually be outdated if the reference specs changes or is updated.
# For the latest version, see https://github.com/oauth-wg/oauth-selective-disclosure-jwt

ISSUER_JWK = {
    "kty": "EC",
    "d": "Ur2bNKuBPOrAaxsRnbSH6hIhmNTxSGXshDSUD1a1y7g",
    "crv": "P-256",
    "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
    "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
}

PRESENTATION_WITHOUT_KB = \
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb" \
    "IkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ" \
    "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL" \
    "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1" \
    "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB" \
    "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2" \
    "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr" \
    "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn" \
    "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu" \
    "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog" \
    "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15" \
    "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1" \
    "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog" \
    "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y" \
    "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH" \
    "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG" \
    "MkhaUSJ9fX0.ZfSxIFLHf7f84WIMqt7Fzme8-586WutjFnXH4TO5XuWG_peQ4hPsqDpi" \
    "MBClkh2aUJdl83bwyyOriqvdFra-bg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgI" \
    "mdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZh" \
    "bWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWl" \
    "sIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhR" \
    "IiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4Z" \
    "TQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngt" \
    "MDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjog" \
    "IjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFu" \
    "eXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZR" \
    "IiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5" \
    "YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92T" \
    "U5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"

PRESENTATION_WITH_KB = \
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb" \
    "IkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ" \
    "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL" \
    "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1" \
    "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB" \
    "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2" \
    "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr" \
    "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn" \
    "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu" \
    "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog" \
    "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15" \
    "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1" \
    "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog" \
    "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y" \
    "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH" \
    "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG" \
    "MkhaUSJ9fX0.ZfSxIFLHf7f84WIMqt7Fzme8-586WutjFnXH4TO5XuWG_peQ4hPsqDpi" \
    "MBClkh2aUJdl83bwyyOriqvdFra-bg~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgI" \
    "mZhbWlseV9uYW1lIiwgIkRvZSJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFk" \
    "ZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5" \
    "IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMi" \
    "fV0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd" \
    "~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~eyJhbGciOiAiRVMyNTYiLCA" \
    "idHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodH" \
    "RwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MjUzNzQ0MTMsICJzZF" \
    "9oYXNoIjogIkF5T0p2TFlQVk1sS2REbGZacnpVeTFrX2ltQ0tfTFZKMzI2Yl94QmtFM0" \
    "0ifQ.B2o5kubh-Dzcd-2v_mWxUMPNM5WSAJqMQTDsGQUXkZXzsN1U5Ou5mr-7iJsCGcx" \
    "6_uU39u-2HKB0xLvYd9BMcQ"


ISSUER_JWT = \
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb" \
    "IkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ" \
    "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL" \
    "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1" \
    "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB" \
    "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2" \
    "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr" \
    "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn" \
    "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu" \
    "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog" \
    "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15" \
    "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1" \
    "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog" \
    "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y" \
    "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH" \
    "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG" \
    "MkhaUSJ9fX0.ZfSxIFLHf7f84WIMqt7Fzme8-586WutjFnXH4TO5XuWG_peQ4hPsqDpi" \
    "MBClkh2aUJdl83bwyyOriqvdFra-bg"

DISCLOSURES = [
    "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
    "WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRy" +
    "ZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9u" +
    "IjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
    "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
    "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0",
]
HOLDER_KB_JWT = \
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY" \
    "3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI" \
    "6IDE3MjUzNzQ0MTMsICJzZF9oYXNoIjogIkF5T0p2TFlQVk1sS2REbGZacnpVeTFrX2l" \
    "tQ0tfTFZKMzI2Yl94QmtFM00ifQ.B2o5kubh-Dzcd-2v_mWxUMPNM5WSAJqMQTDsGQUX" \
    "kZXzsN1U5Ou5mr-7iJsCGcx6_uU39u-2HKB0xLvYd9BMcQ"

AUD = "https://verifier.example.org"
NONCE = "1234567890"

DISCLOSED_CLAIMS = {
    "given_name": "John",
    "family_name": "Doe",
    "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US"
    },
    "nationalities": [
        "US"
    ]
}


def test_sdkwt_parts():
    sdjwt = SdJwt(PRESENTATION_WITH_KB)
    assert ISSUER_JWT == sdjwt.get_issuer_jwt()
    assert DISCLOSURES == sdjwt.get_encoded_disclosures()
    assert HOLDER_KB_JWT == sdjwt.get_holder_key_binding_jwt()


def test_sdjwt_hash_hey_binding():
    sdjwt = SdJwt(PRESENTATION_WITHOUT_KB)
    assert not sdjwt.has_key_binding()

    sdjwt = SdJwt(PRESENTATION_WITH_KB)
    assert sdjwt.has_key_binding()


def test_sd_jwt_verify_issuer_jwt():
    sdjwt = SdJwt(PRESENTATION_WITH_KB)
    sdjwt.verify_issuer_jwt_signature(ISSUER_JWK)


def test_sd_jwt_verify_holder_kb_signature():
    sdjwt = SdJwt(PRESENTATION_WITH_KB)
    sdjwt.verify_holder_kb_jwt_signature()


def test_sd_jwt_verify_holder_kb():
    sdjwt = SdJwt(PRESENTATION_WITH_KB)

    @dataclass
    class TestCase:
        challenge: VerifierChallenge
        expected_result: bool
        explanation: str

    test_cases: list[TestCase] = [
        TestCase(
            challenge={"aud": "https://bad-aud.example", "nonce": "000000"},
            expected_result=False,
            explanation="bad challenge (both aud and nonce are wrong)"
        ),
        TestCase(
            challenge={"aud": AUD, "nonce": "000000"},
            expected_result=False,
            explanation="bad challenge (nonce is wrong)"
        ),
        TestCase(
            challenge={"aud": "https://bad-aud.example", "nonce": NONCE},
            expected_result=False,
            explanation="bad challenge (aud is wrong)"
        ),
        TestCase(
            challenge={"aud": AUD, "nonce": NONCE},
            expected_result=True,
            explanation="valid challenge (challenge aud and nonce are correct)"
        )
    ]

    for i, case in enumerate(test_cases):
        try:
            # bad challenge: should fail
            sdjwt.verify_holder_kb_jwt(case.challenge)
            if case.expected_result is False:
                assert False, f"failed test {i} on holder key binding: test case: {case.explanation}: should have launched a verification exception"
            else:
                assert True
        except Exception as e:
            if case.expected_result is False:
                assert True
            else:
                assert False, f"failed test {i}: test case: {case.explanation}; launched an unxpected verification exception: {e}"


def test_sd_jwt_get_disclosed_claims():
    sdjwt = SdJwt(PRESENTATION_WITH_KB)
    obtained_claims = sdjwt.get_disclosed_claims()
    for claim in DISCLOSED_CLAIMS:
        assert claim in obtained_claims, f"failed to disclose claim {claim}"
        exp_claim_value = DISCLOSED_CLAIMS[claim]
        obt_claim_value = obtained_claims[claim]
        # NOTE: this comparison algorithm for disclosures in general does not work;
        #  the ideal would be a recursive approach is required, but it is ok for this test
        match type(exp_claim_value):
            case builtins.list:
                assert all(v in obt_claim_value for v in exp_claim_value), f"failed proper disclosure of claim {claim}"
            case builtins.dict:
                assert exp_claim_value.items() <= obt_claim_value.items()
            case _:
                assert obt_claim_value == exp_claim_value, f"failed proper disclosure of claim {claim}"
