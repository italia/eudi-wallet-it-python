import json
import logging


import satosa.logging_util as lu
from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import unpad_jwt_header
from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.satosa.exceptions import (
    NotTrustedFederationError, DiscoveryFailedError
)
from pyeudiw.tools.utils import iat_now, exp_from_now
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust import TrustEvaluationHelper
from pyeudiw.trust.trust_anchors import update_trust_anchors_ecs


logger = logging.getLogger(__name__)


class BackendTrust:

    def init_trust_resources(self) -> None:
        # private keys by kid
        self.federations_jwks_by_kids = {
            i['kid']: i for i in self.config['federation']['federation_jwks']
        }
        # dumps public jwks
        self.federation_public_jwks = [
            JWK(i).public_key for i in self.config['federation']['federation_jwks']
        ]
        # we close the connection in this constructor since it must be fork safe and
        # get reinitialized later on, within each fork
        self.update_trust_anchors()

        try:
            self.get_trust_chain()
        except Exception as e:
            logger.critical(
                f"Cannot fetch the trust anchor configuration: {e}"
            )

        self.db_engine.close()
        self._db_engine = None

    def entity_configuration_endpoint(self, context):

        data = self.entity_configuration_as_dict
        if context.qs_params.get('format', '') == 'json':
            return Response(
                json.dumps(data),
                status="200",
                content="application/json"
            )

        return Response(
            self.entity_configuration,
            status="200",
            content="application/entity-statement+jwt"
        )

    def update_trust_anchors(self):
        tas = self.config['federation']['trust_anchors']
        logger.info(
            lu.LOG_FMT.format(
                id="Trust Anchors updates",
                message=f"Trying to update: {tas}"
            )
        )
        for ta in tas:
            try:
                update_trust_anchors_ecs(
                    db=self.db_engine,
                    trust_anchors=[ta],
                    httpc_params=self.config['network']['httpc_params']
                )
            except Exception as e:
                logger.warning(
                    lu.LOG_FMT.format(
                        id=f"Trust Anchor updates",
                        message=f"{ta} update failed: {e}"
                    )
                )
            logger.info(
                lu.LOG_FMT.format(
                    id="Trust Anchor update",
                    message=f"Trust Anchor updated: {ta}"
                )
            )

    @property
    def default_federation_private_jwk(self):
        return tuple(self.federations_jwks_by_kids.values())[0]

    def get_trust_chain(self) -> list:
        try:
            trust_evaluation_helper = TrustEvaluationHelper.build_trust_chain_for_entity_id(
                storage=self.db_engine,
                entity_id=self.client_id,
                entity_configuration=self.entity_configuration,
                httpc_params=self.config['network']['httpc_params']
            )
            self.db_engine.add_or_update_trust_attestation(
                entity_id=self.client_id,
                attestation=trust_evaluation_helper.trust_chain,
                exp=trust_evaluation_helper.exp
            )
            return trust_evaluation_helper.trust_chain

        except (DiscoveryFailedError, EntryNotFound, Exception) as e:
            logger.warning(
                f"Error while building trust chain for client with id: {self.client_id}\n"
                f"{e.__class__.__name__}: {e}"
            )

        return []

    @property
    def entity_configuration_as_dict(self) -> dict:
        ec_payload = {
            "exp": exp_from_now(minutes=self.default_exp),
            "iat": iat_now(),
            "iss": self.client_id,
            "sub": self.client_id,
            "jwks": {
                "keys": self.federation_public_jwks
            },
            "metadata": {
                self.config['federation']["metadata_type"]: self.config['metadata'],
                "federation_entity": self.config['federation']['federation_entity_metadata']
            },
            "authority_hints": self.config['federation']['authority_hints']
        }
        return ec_payload

    @property
    def entity_configuration(self) -> dict:
        data = self.entity_configuration_as_dict
        jwshelper = JWSHelper(self.default_federation_private_jwk)
        return jwshelper.sign(
            protected={
                "alg": self.config['federation']["default_sig_alg"],
                "kid": self.default_federation_private_jwk["kid"],
                "typ": "entity-statement+jwt"
            },
            plain_dict=data
        )

    def _validate_trust(self, context: Context, jws: str) -> TrustEvaluationHelper:
        self._log(
            context,
            level='debug',
            message=(
                "[TRUST EVALUATION] evaluating trust."
            )
        )

        headers = unpad_jwt_header(jws)
        trust_eval = TrustEvaluationHelper(
            self.db_engine,
            httpc_params=self.config['network']['httpc_params'],
            **headers
        )

        try:
            trust_eval.evaluation_method()
        except Exception as e:
            self._log(
                context,
                level='error',
                message=(
                    "[TRUST EVALUATION] failed for "
                    f"{trust_eval.entity_id}: {e}"
                )
            )
            raise NotTrustedFederationError(
                f"{trust_eval.entity_id} is not trusted."
            )
        except EntryNotFound:
            self._log(
                context,
                level='error',
                message=(
                    "[TRUST EVALUATION] not found for "
                    f"{trust_eval.entity_id}"
                )
            )
            raise NotTrustedFederationError(
                f"{trust_eval.entity_id} not found for Trust evaluation."
            )

        return trust_eval
