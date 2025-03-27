from pyeudiw.trust.anchors_loader import AnchorsLoader
from pyeudiw.storage.db_engine import DBEngine
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.tests.settings import CONFIG
from pyeudiw.tests.federation.base import ta_ec_signed
from pyeudiw.tests.x509.test_x509 import gen_chain
from ssl import DER_cert_to_PEM_cert

def test_load_anchors():
    db = DBEngine(CONFIG["storage"])
    pem = DER_cert_to_PEM_cert(gen_chain()[-1])

    anchors = [
        {
            "entity_id": "entity",
            "federation": {
                "entity_configuration": ta_ec_signed
            },
            "x509": {
                "pem": pem
            }
        }
    ]

    AnchorsLoader.load_anchors(db, anchors)

    entity = db.get_trust_anchor("entity")

    assert "entity_id" in entity
    assert "federation" in entity
    assert "entity_configuration" in entity["federation"]

    assert "x509" in entity
    assert "pem" in entity["x509"]
