from datetime import datetime
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.storage.db_engine import DBEngine, TrustType
from pyeudiw.x509.verify import get_expiry_date_from_x5c

class AnchorsLoader:
    @staticmethod
    def load_anchors(db: DBEngine, config: list[dict]) -> None:
        """
        Load the anchors from the database.

        :param db: The database engine
        :type db: DBEngine

        :param config: The configuration
        :type config: list[dict]
        """
        for anchor in config:
            entity_id = anchor.get("entity_id")
            if entity_id is None:
                raise ValueError("An entity_id is required for each trust anchor.")

            if db.has_trust_anchor(entity_id):
                db.add_empty_trust_anchor(anchor)

            if "x509" in anchor:
                db.update_trust_anchor(
                    entity_id, 
                    anchor["x509"], 
                    get_expiry_date_from_x5c([anchor["x509"]["pem"]]),
                    TrustType.X509
                )
            
            if "federation" in anchor:
                decoded_ec = decode_jwt_payload(
                    anchor['federation']['entity_configuration']
                )

                exp = decoded_ec.get("exp")
                if not exp:
                    raise ValueError("The entity configuration must have an exp field.")
                
                date = datetime.fromtimestamp(exp)
                
                db.update_trust_anchor(
                    entity_id, 
                    anchor["federation"]["entity_configuration"], 
                    date, 
                    TrustType.FEDERATION
                )