from uuid import uuid4
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from pyeudiw.tests.trust import correct_config, not_conformant
from pyeudiw.tests.settings import CONFIG
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.tests.trust.mock_trust_handler import MockTrustHandler
from pyeudiw.trust.handler.direct_trust_sd_jwt_vc import DirectTrustSdJwtVc
from pyeudiw.trust.exceptions import TrustConfigurationError

def test_trust_CombinedTrusstEvaluation_handler_loading():    
    trust_ev = CombinedTrustEvaluator.from_config(correct_config, DBEngine(CONFIG["storage"]))

    assert trust_ev
    assert len(trust_ev.handlers) == 2
    assert isinstance(trust_ev.handlers[0], MockTrustHandler)
    assert isinstance(trust_ev.handlers[1], DirectTrustSdJwtVc)


def test_not_conformant_CombinedTrusstEvaluation_handler_loading():
    try:
        CombinedTrustEvaluator.from_config(not_conformant, DBEngine(CONFIG["storage"]))
        assert False
    except TrustConfigurationError:
        assert True

def test_if_no_conf_default_handler_instanciated():
    trust_ev = CombinedTrustEvaluator.from_config({}, DBEngine(CONFIG["storage"]))

    assert len(trust_ev.handlers) == 1
    assert isinstance(trust_ev.handlers[0], DirectTrustSdJwtVc)

def test_public_key_and_metadata_retrive():
    db_engine = DBEngine(CONFIG["storage"])

    trust_ev = CombinedTrustEvaluator.from_config(correct_config, db_engine)

    uuid_url = f"http://{uuid4()}.issuer.it"

    pub_keys = trust_ev.get_public_keys(uuid_url)
    trust_source = db_engine.get_trust_source(uuid_url)

    assert trust_source
    assert trust_source["keys"][0]["kid"] == "qTo9RGpuU_CSolt6GZmndLyPXJJa48up5dH1YbxVDPs"
    assert trust_source["metadata"] == {"json_key": "json_value"}

    assert pub_keys[0]["kid"] == "qTo9RGpuU_CSolt6GZmndLyPXJJa48up5dH1YbxVDPs"

    metadata = trust_ev.get_metadata(uuid_url)

    assert metadata == {"json_key": "json_value"}