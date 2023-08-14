from pyeudiw.federation.statements import (
    get_entity_configurations,
    EntityStatement
)
from pyeudiw.storage.db_engine import DBEngine


def update_trust_anchors_ecs(trust_anchors: list, db: DBEngine, httpc_params: dict):
    ta_ecs = get_entity_configurations(
        trust_anchors, httpc_params=httpc_params
    )

    for jwt in ta_ecs:
        ec = EntityStatement(jwt, httpc_params=httpc_params)
        if not ec.validate_by_itself():
            # TODO: log warning
            pass

        db.add_trust_anchor(
            entity_id=ec.sub,
            entity_configuration=jwt,
            exp=ec.exp
        )
