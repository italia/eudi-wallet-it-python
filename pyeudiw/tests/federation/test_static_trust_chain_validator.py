import copy
import uuid
import unittest.mock as mock
from unittest.mock import Mock
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator
import pyeudiw.federation.trust_chain_validator as tcv

from pyeudiw.tests.settings import httpc_params


from . base import (
    EXP,
    JWS,
    NOW,
    intermediate_ec_signed,
    intermediate_es_wallet,
    intermediate_es_wallet_signed,
    intermediate_jwk,
    leaf_wallet_signed,
    leaf_wallet_jwk,
    ta_es,
    ta_es_signed,
    ta_jwk,
    trust_chain_wallet
)


def test_is_valid():
    assert StaticTrustChainValidator(
        trust_chain_wallet, [ta_jwk.serialize()], httpc_params=httpc_params).is_valid


invalid_intermediate = copy.deepcopy(intermediate_es_wallet)
invalid_leaf_jwk = copy.deepcopy(leaf_wallet_jwk.serialize())
invalid_leaf_jwk["kid"] = str(uuid.uuid4())

invalid_intermediate["jwks"]['keys'] = [invalid_leaf_jwk]

intermediate_signer = JWS(
    invalid_intermediate, alg="RS256",
    typ="application/entity-statement+jwt"
)
invalid_intermediate_es_wallet_signed = intermediate_signer.sign_compact(
    [intermediate_jwk]
)

invalid_trust_chain = [
    leaf_wallet_signed,
    invalid_intermediate_es_wallet_signed,
    ta_es_signed
]


def test_is_valid_equals_false():
    assert not StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params
    ).is_valid


def test_retrieve_ec():
    tcv.get_entity_configurations = Mock(return_value=[leaf_wallet_signed])

    assert tcv.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params)._retrieve_ec("https://trust-anchor.example.org") == leaf_wallet_signed


def test_retrieve_ec_fails():
    tcv.get_entity_configurations = Mock(return_value=[])

    try:
        StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params)._retrieve_ec("https://trust-anchor.example.org")
    except tcv.HttpError as e:
        return


def test_retrieve_es():
    tcv.get_entity_statements = Mock(return_value=ta_es)

    assert tcv.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params)._retrieve_es("https://trust-anchor.example.org", "https://trust-anchor.example.org") == ta_es


def test_retrieve_es_output_is_none():
    tcv.get_entity_statements = Mock(return_value=None)

    assert tcv.StaticTrustChainValidator(
        invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params)._retrieve_es("https://trust-anchor.example.org", "https://trust-anchor.example.org") == None


def test_update_st_ec_case():
    def mock_method(*args, **kwargs):
        # if args[0] == "https://wallet-provider.example.org":
        return [leaf_wallet_signed]

        # raise Exception("Wrong issuer")

    with mock.patch.object(tcv, "get_entity_configurations", mock_method):
        assert tcv.StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params)._update_st(leaf_wallet_signed) == leaf_wallet_signed


def test_update_st_es_case_source_endpoint():
    ta_es = {
        "exp": EXP,
        "iat": NOW,
        "iss": "https://trust-anchor.example.org",
        "sub": "https://intermediate.eidas.example.org",
        'jwks': {"keys": []},
        "source_endpoint": "https://trust-anchor.example.org/fetch"
    }

    ta_signer = JWS(ta_es, alg="RS256", typ="application/entity-statement+jwt")
    ta_es_signed = ta_signer.sign_compact([ta_jwk])

    def mock_method(*args, **kwargs):
        return leaf_wallet_signed

    with mock.patch.object(tcv, "get_entity_statements", mock_method):
        _t = tcv.StaticTrustChainValidator(
            invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params
        )
        assert _t._update_st(ta_es_signed) == leaf_wallet_signed
        assert not _t.is_valid


def test_update_st_es_case_no_source_endpoint():
    ta_es = {
        "exp": EXP,
        "iat": NOW,
        "iss": "https://trust-anchor.example.org",
        "sub": "https://intermediate.eidas.example.org",
        'jwks': {"keys": []},
    }

    ta_signer = JWS(ta_es, alg="RS256", typ="application/entity-statement+jwt")
    ta_es_signed = ta_signer.sign_compact([ta_jwk])

    def mock_method_ec(*args, **kwargs):
        return [intermediate_es_wallet_signed]

    def mock_method_es(*args, **kwargs):
        return leaf_wallet_signed

    with mock.patch.object(tcv, "get_entity_statements", mock_method_es):
        with mock.patch.object(tcv, "get_entity_configurations", mock_method_ec):
            _t = tcv.StaticTrustChainValidator(
                invalid_trust_chain, [ta_jwk.serialize()], httpc_params=httpc_params
            )
            assert _t._update_st(ta_es_signed) == leaf_wallet_signed
