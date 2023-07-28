import uuid
from pyeudiw.jwk import JWK
from pyeudiw.sd_jwt import (
    issue_sd_jwt, verify_sd_jwt, _adapt_keys, load_specification_from_yaml_string)


from sd_jwt.holder import SDJWTHolder

settings = {
    "issuer": "http://test.com",
    "default_exp": 60,
    "sd_specification": """
        user_claims:
            !sd unique_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            !sd given_name: "Mario"
            !sd family_name: "Rossi"
            !sd birthdate: "1980-01-10"
            !sd place_of_birth:
                country: "IT"
                locality: "Rome"
            !sd tax_id_code: "TINIT-XXXXXXXXXXXXXXXX"

        holder_disclosed_claims:
            { "given_name": "Mario", "family_name": "Rossi", "place_of_birth": {country: "IT", locality: "Rome"} }

        key_binding: True
    """,
    "no_randomness": True
}

sd_specification = load_specification_from_yaml_string(
    settings["sd_specification"])


def test_issue_sd_jwt():
    issuer_jwk = JWK()
    holder_jwk = JWK()

    issue_sd_jwt(
        sd_specification,
        settings,
        issuer_jwk,
        holder_jwk
    )


def test_verify_sd_jwt():
    issuer_jwk = JWK()
    holder_jwk = JWK()

    issued_jwt = issue_sd_jwt(
        sd_specification,
        settings,
        issuer_jwk,
        holder_jwk
    )

    adapted_keys = _adapt_keys(
        settings,
        issuer_jwk,
        holder_jwk
    )

    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format="compact",
    )
    sdjwt_at_holder.create_presentation(
        sd_specification,
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        adapted_keys["holder_key"] if sd_specification.get(
            "key_binding", False) else None,
    )

    verified_payload = verify_sd_jwt(
        sdjwt_at_holder.sd_jwt_presentation,
        sd_specification,
        settings,
        issuer_jwk,
        holder_jwk
    )
