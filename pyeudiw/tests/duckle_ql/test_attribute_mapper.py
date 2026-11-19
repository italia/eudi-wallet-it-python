import pytest

from pyeudiw.duckle_ql.attribute_mapper import (
    extract_claims,
    flatten_namespace,
    paths_for_claim_sets,
)
from pyeudiw.duckle_ql.credential import Claim

DATA_TOKEN_DC_SD_JWT = data = {
    "iss": "https://credential_issuer.example.org",
    "iat": 1745967705,
    "exp": 1745969685,
    "cnf": {
        "jwk": {
            "kty": "EC",
            "alg": "ES256",
            "crv": "P-256",
            "x": "Gja5v5i8l7dMmOdyH5X2vg90NC1C10s1cpzYNYepzAU",
            "y": "o-dcILSXq6--t-w_5kkX3qtQQL3i5oO-EYAjDd_famU",
        }
    },
    "given_name": "Mario",
    "tax_id_code": "TINIT-XXXXXXXXXXXXXXXX",
    "family_name": "Rossi",
    "address": {"province": "RM", "zipcode": "0042"},
}

DATA_TOKEN_MSO_MDOC = {
    "eu.europa.ec.eudiw.pid.1": {
        "wallet_link": "https://user.example.com/wallet/abc123",
        "wallet_name": "Mario’s eID Wallet",
    },
    "eu.europa.ec.eudiw.pid.2": {
        "wallet_documents": {"typo": "CIE"},
    },
}


def test_extract_claims_from_token_dc_sd_jwt():
    nested_paths = [{"path": ["address", "zipcode"]}, {"path": ["given_name"]}]
    assert extract_claims(DATA_TOKEN_DC_SD_JWT, nested_paths) == {
        "address": {"zipcode": "0042"},
        "given_name": "Mario",
    }

    flat_paths = [{"path": ["given_name"]}]
    assert extract_claims(DATA_TOKEN_DC_SD_JWT, flat_paths) == {"given_name": "Mario"}


def test_missing_claim_raises_from_token_dc_sd_jwt():
    paths = [{"path": ["address", "state"]}]
    with pytest.raises(ValueError) as excinfo:
        extract_claims(DATA_TOKEN_DC_SD_JWT, paths)

    assert "Missing claims: address.state" in str(excinfo.value)


def test_extract_claims_from_token_mso_mdoc():
    nested_paths = [{"path": ["wallet_documents", "typo"]}, {"path": ["wallet_link"]}]
    assert extract_claims(flatten_namespace(DATA_TOKEN_MSO_MDOC), nested_paths) == {
        "wallet_documents": {"typo": "CIE"},
        "wallet_link": "https://user.example.com/wallet/abc123",
    }

    flat_paths = [{"path": ["wallet_link"]}]
    assert extract_claims(flatten_namespace(DATA_TOKEN_MSO_MDOC), flat_paths) == {
        "wallet_link": "https://user.example.com/wallet/abc123"
    }


def test_missing_claim_raises_from_token_mso_mdoc():
    paths = [{"path": ["address", "state"]}]
    with pytest.raises(ValueError) as excinfo:
        extract_claims(flatten_namespace(DATA_TOKEN_MSO_MDOC), paths)

    assert "Missing claims: address.state" in str(excinfo.value)


def test_flatten_namespace_for_token_mso_mdoc():
    assert flatten_namespace(DATA_TOKEN_MSO_MDOC) == {
        "wallet_link": "https://user.example.com/wallet/abc123",
        "wallet_name": "Mario’s eID Wallet",
        "wallet_documents": {"typo": "CIE"},
    }


CLAIMS_WITH_OPTIONAL = [
    Claim(id="given_name", path=["given_name"]),
    Claim(id="family_name", path=["family_name"]),
    Claim(id="tax_id_code", path=["tax_id_code"]),
]

CLAIM_SETS_OPTIONAL_TAX_ID = [
    ["given_name", "family_name"],
    ["given_name", "family_name", "tax_id_code"],
]


def test_paths_for_claim_sets_without_claim_sets_requires_all():
    data = {"given_name": "Mario", "family_name": "Rossi", "tax_id_code": "TINIT-X"}
    paths = paths_for_claim_sets(CLAIMS_WITH_OPTIONAL, None, data)
    assert paths == [
        {"path": ["given_name"]},
        {"path": ["family_name"]},
        {"path": ["tax_id_code"]},
    ]
    assert extract_claims(data, paths)["tax_id_code"] == "TINIT-X"


def test_paths_for_claim_sets_accepts_minimal_set_without_optional():
    data = {"given_name": "Mario", "family_name": "Rossi"}
    paths = paths_for_claim_sets(CLAIMS_WITH_OPTIONAL, CLAIM_SETS_OPTIONAL_TAX_ID, data)
    assert paths == [{"path": ["given_name"]}, {"path": ["family_name"]}]
    assert extract_claims(data, paths) == {
        "given_name": "Mario",
        "family_name": "Rossi",
    }


def test_paths_for_claim_sets_prefers_first_satisfied_set():
    data = {
        "given_name": "Mario",
        "family_name": "Rossi",
        "tax_id_code": "TINIT-X",
    }
    paths = paths_for_claim_sets(CLAIMS_WITH_OPTIONAL, CLAIM_SETS_OPTIONAL_TAX_ID, data)
    assert paths == [{"path": ["given_name"]}, {"path": ["family_name"]}]


def test_paths_for_claim_sets_missing_required_raises():
    data = {"given_name": "Mario"}
    with pytest.raises(ValueError) as excinfo:
        paths_for_claim_sets(CLAIMS_WITH_OPTIONAL, CLAIM_SETS_OPTIONAL_TAX_ID, data)
    assert "Missing claims: family_name" in str(excinfo.value)
