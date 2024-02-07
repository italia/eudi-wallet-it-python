import logging
from pyeudiw.federation.statements import (
    get_entity_configurations,
    EntityStatement
)
from pyeudiw.storage.db_engine import DBEngine

logger = logging.getLogger(__name__)


def update_trust_anchors_ecs(trust_anchors: list[str], db: DBEngine, httpc_params: dict) -> None:
    """
    Update the trust anchors entity configurations.

    :param trust_anchors: The trust anchors
    :type trust_anchors: list
    :param db: The database engine
    :type db: DBEngine
    :param httpc_params: The HTTP client parameters
    :type httpc_params: dict
    """

    ta_ecs = get_entity_configurations(
        trust_anchors, httpc_params=httpc_params
    )

    for jwt in ta_ecs:
        if isinstance(jwt, bytes):
            jwt = jwt.decode()

        ec = EntityStatement(jwt, httpc_params=httpc_params)
        if not ec.validate_by_itself():
            logger.warning(
                f"The trust anchor failed the validation of its EntityConfiguration {ec}")

        db.add_trust_anchor(
            entity_id=ec.sub,
            entity_configuration=ec.jwt,
            exp=ec.exp
        )
