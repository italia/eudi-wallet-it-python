from uuid import uuid4

import time
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.settings import CONFIG
from pyeudiw.tests.trust import correct_config, not_conformant
from pyeudiw.tests.trust.mock_trust_handler import MockTrustHandler
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.trust.exceptions import TrustConfigurationError
from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc


def test_trust_CombinedTrusstEvaluation_handler_loading():
    trust_ev = CombinedTrustEvaluator.from_config(
        correct_config,
        DBEngine(CONFIG["storage"]),
        default_client_id="default-client-id",
    )

    assert trust_ev
    assert len(trust_ev.handlers) == 2
    assert isinstance(trust_ev.handlers[0], MockTrustHandler)
    assert isinstance(trust_ev.handlers[1], DirectTrustSdJwtVc)


def test_not_conformant_CombinedTrusstEvaluation_handler_loading():
    try:
        CombinedTrustEvaluator.from_config(
            not_conformant,
            DBEngine(CONFIG["storage"]),
            default_client_id="default-client-id",
        )
        assert False
    except TrustConfigurationError:
        assert True


def test_if_no_conf_default_handler_instanciated():
    trust_ev = CombinedTrustEvaluator.from_config(
        {}, DBEngine(CONFIG["storage"]), default_client_id="default-client-id"
    )
    # both jar issuer and direct trust sd jwt vc are default if not trust handlers are configured
    assert len(trust_ev.handlers) == 2
    assert isinstance(trust_ev.handlers[0], DirectTrustSdJwtVc)


def test_public_key_and_metadata_retrive():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(
        {
            "mock": {
                "module": "pyeudiw.tests.trust.mock_trust_handler",
                "class": "MockTrustHandler",
                "config": {},
            },
                
        }, db_engine, default_client_id="default-client-id", mode="update_first"
    )

    uuid_url = f"http://{uuid4()}.issuer.it"

    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'trust_param_key': 'trust_param_value'}}
    metadata = trust_ev.get_metadata()

    assert metadata["default_key"] == "default_value"
    assert len(metadata["jwks"]["keys"]) == 2
    assert "d" not in metadata["jwks"]["keys"][0]
    assert "d" not in metadata["jwks"]["keys"][1]

    keys = trust_ev.get_public_keys()

    assert len(keys) == 2
    assert "d" not in keys[0]
    assert "d" not in keys[1]

def test_update_first_strategy():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(
        {
            "mock": {
                "module": "pyeudiw.tests.trust.mock_trust_handler",
                "class": "UpdateTrustHandler",
                "config": {},
            },
                
        }, db_engine, default_client_id="default-client-id"
    )

    uuid_url = f"http://{uuid4()}.issuer.it"

    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'trust_param_key': 'trust_param_value'}}
    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'updated_trust_param_key': 'updated_trust_param_value'}}


def test_cache_first_strategy():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(
        {
            "mock": {
                "module": "pyeudiw.tests.trust.mock_trust_handler",
                "class": "UpdateTrustHandler",
                "config": {},
            },
                
        }, db_engine, default_client_id="default-client-id", mode="cache_first"
    )

    uuid_url = f"http://{uuid4()}.issuer.it"

    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'trust_param_key': 'trust_param_value'}}
    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'trust_param_key': 'trust_param_value'}}

def test_cache_first_strategy_expired():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(
        {
            "mock": {
                "module": "pyeudiw.tests.trust.mock_trust_handler",
                "class": "UpdateTrustHandler",
                "config": {
                    "exp": 0
                },
            },
                
        }, db_engine, default_client_id="default-client-id", mode="cache_first"
    )

    uuid_url = f"http://{uuid4()}.issuer.it"

    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'trust_param_key': 'trust_param_value'}}
    time.sleep(1)
    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'updated_trust_param_key': 'updated_trust_param_value'}}

def test_cache_first_strategy_expired_revoked():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(
        {
            "mock": {
                "module": "pyeudiw.tests.trust.mock_trust_handler",
                "class": "UpdateTrustHandler",
                "config": {},
            },
                
        }, db_engine, default_client_id="default-client-id", mode="cache_first"
    )

    uuid_url = f"http://{uuid4()}.issuer.it"

    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'trust_param_key': 'trust_param_value'}}

    trust_ev.revoke(uuid_url)

    assert trust_ev.is_revoked(uuid_url) == True
    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'updated_trust_param_key': 'updated_trust_param_value'}}

def test_cache_first_strategy_expired_force_update():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(
        {
            "mock": {
                "module": "pyeudiw.tests.trust.mock_trust_handler",
                "class": "UpdateTrustHandler",
                "config": {},
            },
                
        }, db_engine, default_client_id="default-client-id", mode="cache_first"
    )

    uuid_url = f"http://{uuid4()}.issuer.it"

    assert trust_ev.get_jwt_header_trust_parameters(uuid_url) == {'trust_param_name': {'trust_param_key': 'trust_param_value'}}
    assert trust_ev.get_jwt_header_trust_parameters(uuid_url, force_update=True) == {'trust_param_name': {'updated_trust_param_key': 'updated_trust_param_value'}}