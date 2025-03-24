from pyeudiw.storage.db_engine import DBEngine

class AnchorsLoader:
    @staticmethod
    def load_anchors(db: DBEngine, config: list[dict]) -> dict:
        """
        Load the anchors from the database.
        """
        for anchor in config:
            db.add_trust_anchor(anchor)