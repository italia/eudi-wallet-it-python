from pyeudiw.sd_jwt.holder import SDJWTHolder
from pyeudiw.sd_jwt.issuer import SDJWTIssuer
from pyeudiw.sd_jwt.utils.demo_utils import get_jwk
from pyeudiw.sd_jwt.verifier import SDJWTVerifier


def test_e2e(testcase, settings):
    settings.update(testcase.get("settings_override", {}))
    seed = settings["random_seed"]
    demo_keys = get_jwk(settings["key_settings"], True, seed)
    use_decoys = testcase.get("add_decoy_claims", False)
    
    
    serialization_format = testcase.get("serialization_format", "compact")

    extra_header_parameters = {"typ": "testcase+sd-jwt"}
    extra_header_parameters.update(testcase.get("extra_header_parameters", {}))

    # Issuer: Produce SD-JWT and issuance format for selected example

    user_claims = {"iss": settings["identifiers"]["issuer"]}
    user_claims.update(testcase["user_claims"])

    SDJWTIssuer.unsafe_randomness = True
    sdjwt_at_issuer = SDJWTIssuer(
        user_claims,
        demo_keys["issuer_keys"],
        demo_keys["holder_key"] if testcase.get("key_binding", False) else None,
        add_decoy_claims=use_decoys,
        serialization_format=serialization_format,
        extra_header_parameters=extra_header_parameters,
    )

    output_issuance = sdjwt_at_issuer.sd_jwt_issuance

    # Holder
    sdjwt_at_holder = SDJWTHolder(
        output_issuance,
        serialization_format=serialization_format,
    )
    
    sdjwt_at_holder.create_presentation(
        testcase["holder_disclosed_claims"],
        settings["key_binding_nonce"] if testcase.get("key_binding", False) else None,
        (
            settings["identifiers"]["verifier"]
            if testcase.get("key_binding", False)
            else None
        ),
        demo_keys["holder_key"] if testcase.get("key_binding", False) else None,
    )
    
    output_holder = sdjwt_at_holder.sd_jwt_presentation

    # Verifier
    sdjwt_header_parameters = {}

    def cb_get_issuer_key(issuer, header_parameters):
        if isinstance(header_parameters, dict):
            sdjwt_header_parameters.update(header_parameters)
        return demo_keys["issuer_public_keys"]

    sdjwt_at_verifier = SDJWTVerifier(
        output_holder,
        cb_get_issuer_key,
        (
            settings["identifiers"]["verifier"]
            if testcase.get("key_binding", False)
            else None
        ),
        settings["key_binding_nonce"] if testcase.get("key_binding", False) else None,
        serialization_format=serialization_format,
    )
    verified = sdjwt_at_verifier.get_verified_payload()

    expected_claims = testcase["expect_verified_user_claims"]
    expected_claims["iss"] = settings["identifiers"]["issuer"]

    if testcase.get("key_binding", False):
        expected_claims["cnf"] = {
            "jwk": demo_keys["holder_key"].export_public(as_dict=True)
        }

    assert verified == expected_claims, f"Verified payload mismatch: {verified} != {expected_claims}"

    # We don't compare header parameters for JSON Serialization for now
    if serialization_format == "compact":
        expected_header_parameters = {
            "alg": testcase.get("sign_alg", "ES256"),
            "typ": "testcase+sd-jwt",
        }
        expected_header_parameters.update(extra_header_parameters)

        # Assert degli header JWS
        assert sdjwt_header_parameters == expected_header_parameters, (
            f"Header parameters mismatch: {sdjwt_header_parameters} != {expected_header_parameters}"
        )
