import uuid

from sd_jwt.holder import SDJWTHolder

from pyeudiw.jwk import JWK
from pyeudiw.jwt import DEFAULT_SIG_KTY_MAP
from pyeudiw.sd_jwt import (
    _adapt_keys,
    issue_sd_jwt,
    load_specification_from_yaml_string,
    verify_sd_jwt,
    import_pyca_pri_rsa
)

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
    """
}

sd_specification = load_specification_from_yaml_string(
    settings["sd_specification"])


def test_issue_sd_jwt():
    issuer_jwk = JWK(key_type='RSA')
    holder_jwk = JWK(key_type='RSA')

    issue_sd_jwt(
        sd_specification,
        settings,
        issuer_jwk,
        holder_jwk
    )


def test_verify_sd_jwt():
    issuer_jwk = JWK(key_type='RSA')
    # issuer_jwk = import_pyca_pri_rsa(issuer_jwk.key.priv_key, kid=issuer_jwk.kid)
    holder_jwk = JWK(key_type='RSA')

    issued_jwt = issue_sd_jwt(
        sd_specification,
        settings,
        issuer_jwk,
        holder_jwk
    )

    adapted_keys = _adapt_keys(
        issuer_jwk,
        holder_jwk
    )

    sdjwt_at_holder = SDJWTHolder(
        issued_jwt["issuance"],
        serialization_format="compact",
    )

    sdjwt_at_holder.create_presentation(
        sd_specification,
        nonce=str(uuid.uuid4()),
        aud=str(uuid.uuid4()),
        holder_key=(
            import_pyca_pri_rsa(holder_jwk.key.priv_key, kid=holder_jwk.kid)
            if sd_specification.get("key_binding", False)
            else None
        ),
        sign_alg=DEFAULT_SIG_KTY_MAP[holder_jwk.key.kty],
    )

    verified_payload = verify_sd_jwt(
        sdjwt_at_holder.sd_jwt_presentation,
        issuer_jwk,
        holder_jwk,
        settings,
    )
