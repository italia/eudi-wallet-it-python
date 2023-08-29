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
    NotTrustedFederationError
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
            self.my_trust_chain
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

    @property
    def my_trust_chain(self) -> None:
        # TODO: move it to the TrustEvaluationHelper
        trust_chain = []
        is_good = False
        try:
            db_chain = self.db_engine.get_trust_attestation(
                self.client_id
            )
            trust_eval = TrustEvaluationHelper(
                self.db_engine,
                httpc_params=self.config['network']['httpc_params'],
                trust_chain=db_chain["federation"]["chain"]
            )
            is_good = trust_eval.evaluation_method()
            trust_chain = db_chain['federation']['chain']
            exp = db_chain['federation']['exp']
        except (EntryNotFound, Exception):
            pass

        if not is_good:
            # TODO: move this trust chain discovery into the trust helper
            ta_eid = self.config['federation']['trust_anchors'][0]
            _ta_ec = self.db_engine.get_trust_anchor(
                entity_id=ta_eid
            )
            ta_ec = _ta_ec['federation']['entity_configuration']

            tcbuilder = TrustChainBuilder(
                subject=self.client_id,
                trust_anchor=ta_eid,
                trust_anchor_configuration=ta_ec,
                subject_configuration=self.entity_configuration,
                httpc_params=self.config['network']['httpc_params']
            )
            is_good = tcbuilder.is_valid
            trust_chain = tcbuilder.get_trust_chain()
            exp = tcbuilder.exp

        if is_good:
            self.db_engine.add_or_update_trust_attestation(
                entity_id=self.client_id,
                attestation=trust_chain,
                exp=exp
            )
        return trust_chain

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
                self.config['federation']["metadata_type"]: self.config['metadata']
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
