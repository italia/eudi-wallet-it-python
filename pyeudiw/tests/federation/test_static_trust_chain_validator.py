import copy
import uuid
import unittest.mock as mock
from unittest.mock import Mock
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
import pyeudiw.federation.trust_chain_validator as tcv_test

from . base import EXP, JWS, NOW, intermediate_ec, intermediate_es, intermediate_jwk, leaf_ec_signed, leaf_jwk, ta_es, ta_es_signed, ta_jwk, trust_chain


def test_is_valid():
    assert StaticTrustChainValidator(
        trust_chain, [ta_jwk.serialize()]).is_valid


invalid_intermediate = copy.deepcopy(intermediate_es)
invalid_leaf_jwk = copy.deepcopy(leaf_jwk.serialize())
invalid_leaf_jwk["kid"] = str(uuid.uuid4())

invalid_intermediate["jwks"]['keys'] = [invalid_leaf_jwk]

intermediate_signer = JWS(
    invalid_intermediate, alg="RS256",
    typ="application/entity-statement+jwt"
)
invalid_intermediate_es_signed = intermediate_signer.sign_compact([
                                                                  intermediate_jwk])

invalid_trust_chain = [
    leaf_ec_signed,
    invalid_intermediate_es_signed,
    ta_es_signed
]


def test_is_valid_equals_false():
    assert StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()]).is_valid == False


def test_retrieve_ec():
    tcv_test.get_entity_configurations = Mock(return_value=[leaf_ec_signed])

    assert tcv_test.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()])._retrieve_ec("https://trust-anchor.example.eu") == leaf_ec_signed


def test_retrieve_ec_fails():
    tcv_test.get_entity_configurations = Mock(return_value=[])

    try:
        StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()])._retrieve_ec("https://trust-anchor.example.eu")
    except tcv_test.HttpError as e:
        return


def test_retrieve_es():
    tcv_test.get_entity_statements = Mock(return_value=ta_es)

    assert tcv_test.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()])._retrieve_es("https://trust-anchor.example.eu", "https://trust-anchor.example.eu") == ta_es


def test_retrieve_es_output_is_none():
    tcv_test.get_entity_statements = Mock(return_value=None)

    assert tcv_test.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()])._retrieve_es("https://trust-anchor.example.eu", "https://trust-anchor.example.eu") == None


def test_update_st_ec_case():
    def mock_method(*args, **kwargs):
        if args[0] == "https://rp.example.it":
            return [leaf_ec_signed]

        raise Exception("Wrong issuer")

    with mock.patch.object(tcv_test, "get_entity_configurations", mock_method):
        assert tcv_test.StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()])._update_st(leaf_ec_signed) == leaf_ec_signed


def test_update_st_es_case_source_endpoint():
    ta_es = {
        "exp": EXP,
        "iat": NOW,
        "iss": "https://trust-anchor.example.eu",
        "sub": "https://intermediate.eidas.example.org",
        'jwks': {"keys": []},
        "source_endpoint": "https://rp.example.it"
    }

    ta_signer = JWS(ta_es, alg="RS256", typ="application/entity-statement+jwt")
    ta_es_signed = ta_signer.sign_compact([ta_jwk])

    def mock_method(*args, **kwargs):
        if args[0] == "https://rp.example.it":
            return leaf_ec_signed

        raise Exception("Wrong issuer")

    with mock.patch.object(tcv_test, "get_entity_statements", mock_method):
        assert tcv_test.StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()])._update_st(ta_es_signed) == leaf_ec_signed


def test_update_st_es_case_source_endpoint():
    intermediate_signer = JWS(intermediate_ec, alg="RS256",
                              typ="application/entity-statement+jwt")
    intermediate_ec_signed = intermediate_signer.sign_compact(
        [intermediate_jwk])

    ta_es = {
        "exp": EXP,
        "iat": NOW,
        "iss": "https://trust-anchor.example.eu",
        "sub": "https://intermediate.eidas.example.org",
        'jwks': {"keys": []},
    }

    ta_signer = JWS(ta_es, alg="RS256", typ="application/entity-statement+jwt")
    ta_es_signed = ta_signer.sign_compact([ta_jwk])

    def mock_method_ec(*args, **kwargs):
        if args[0] == "https://trust-anchor.example.eu":
            return [intermediate_ec_signed]
        raise Exception("Wrong issuer")

    def mock_method_es(*args, **kwargs):
        if args[0] == "https://verifier.example.org/fetch":
            return leaf_ec_signed
        raise Exception("Wrong issuer")

    with mock.patch.object(tcv_test, "get_entity_statements", mock_method_es):
        with mock.patch.object(tcv_test, "get_entity_configurations", mock_method_ec):
            assert tcv_test.StaticTrustChainValidator(
                invalid_trust_chain, [ta_jwk.serialize()])._update_st(ta_es_signed) == leaf_ec_signed
