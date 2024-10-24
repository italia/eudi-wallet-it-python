import logging
from typing import Any
from jwcrypto.jwk import JWK

import json

from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header
from pyeudiw.satosa.exceptions import (DiscoveryFailedError,
                                       NotTrustedFederationError)
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust import TrustEvaluationHelper
from pyeudiw.trust.trust_anchors import update_trust_anchors_ecs


from pyeudiw.federation.policy import TrustChainPolicy
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.trust.interface import TrustEvaluator

logger = logging.getLogger(__name__)


class FederationTrustModel(TrustEvaluator):
    _ISSUER_METADATA_TYPE = "openid_credential_issuer"

    def __init__(self, **kwargs):
        # TODO; qui c'è dentro tutta la ciccia: trust chain verification, root of trust, etc
        self.metadata_policy_resolver = TrustChainPolicy()
        self.federation_jwks = kwargs.get("federation_jwks", [])
        pass

    def get_public_keys(self, issuer):
        public_keys = [JWK(i).as_public_dict() for i in self.federation_jwks]

        return public_keys

    def _verify_trust_chain(self, trust_chain: list[str]):
        # TODO: qui c'è tutta la ciccia, ma si può fare copia incolla da terze parti (specialmente di pyeudiw.trust.__init__)
        raise NotImplementedError

    def get_verified_key(self, issuer: str, token_header: dict) -> JWK:
        # (1) verifica trust chain
        kid: str = token_header.get("kid", None)
        if not kid:
            raise ValueError("missing claim [kid] in token header")
        trust_chain: list[str] = token_header.get("trust_chain", None)
        if not trust_chain:
            raise ValueError("missing trust chain in federation token")
        if not isinstance(trust_chain, list):
            raise ValueError*("invalid format of header claim [trust_claim]")
        self._verify_trust_chain(trust_chain)  # TODO: check whick exceptions this might raise

        # (2) metadata parsing ed estrazione Jwk set
        # TODO: wrap in something that implements VciJwksSource
        # apply policy of traust anchor only?
        issuer_entity_configuration = trust_chain[0]
        anchor_entity_configuration = trust_chain[-1]
        issuer_payload: dict = decode_jwt_payload(issuer_entity_configuration)
        anchor_payload = decode_jwt_payload(anchor_entity_configuration)
        trust_anchor_policy = anchor_payload.get("metadata_policy", {})
        final_issuer_metadata = self.metadata_policy_resolver.apply_policy(issuer_payload, trust_anchor_policy)
        metadata: dict = final_issuer_metadata.get("metadata", None)
        if not metadata:
            raise ValueError("missing or invalid claim [metadata] in entity configuration")
        issuer_metadata: dict = metadata.get(FederationTrustModel._ISSUER_METADATA_TYPE, None)
        if not issuer_metadata:
            raise ValueError(f"missing or invalid claim [metadata.{FederationTrustModel._ISSUER_METADATA_TYPE}] in entity configuration")
        issuer_keys: list[dict] = issuer_metadata.get("jwks", {}).get("keys", [])
        if not issuer_keys:
            raise ValueError(f"missing or invalid claim [metadata.{FederationTrustModel._ISSUER_METADATA_TYPE}.jwks.keys] in entity configuration")
        # check issuer = entity_id
        if issuer != (obt_iss := final_issuer_metadata.get("iss", "")):
            raise ValueError(f"invalid issuer metadata: expected '{issuer}', obtained '{obt_iss}'")

        # (3) dato il set completo, fa il match per kid tra l'header e il jwk set
        found_jwks: list[dict] = []
        for key in issuer_keys:
            obt_kid: str = key.get("kid", "")
            if kid == obt_kid:
                found_jwks.append(key)
        if len(found_jwks) != 1:
            raise ValueError(f"unable to uniquely identify a key with kid {kid} in appropriate section of issuer entity configuration")
        try:
            return JWK(**found_jwks[0])
        except Exception as e:
            raise ValueError(f"unable to parse issuer jwk: {e}")

    # ---------------------------
    # TODO: sistema da qui in giù
    # ---------------------------

    # def __getattribute__(self, name: str) -> Any:
    #     if hasattr(self, name):
    #         return getattr(self, name)
    #     logger.critical("se vedi questo messaggio: sei perduto")
    #     return None

    def init_trust_resources(self) -> None:
        """
        Initializes the trust resources.
        """

        # private keys by kid
        self.federations_jwks_by_kids = {
            i['kid']: i for i in self.config['trust']['federation']['config']['federation_jwks']
        }
        # dumps public jwks
        self.federation_public_jwks = [
            JWK(i).public_key for i in self.config['trust']['federation']['config']['federation_jwks']
        ]
        # we close the connection in this constructor since it must be fork safe and
        # get reinitialized later on, within each fork
        self.update_trust_anchors()

        try:
            self.get_backend_trust_chain()
        except Exception as e:
            self._log_critical(
                "Backend Trust",
                f"Cannot fetch the trust anchor configuration: {e}"
            )

        self.db_engine.close()
        self._db_engine = None

    def entity_configuration_endpoint(self, context: Context) -> Response:
        """
        Entity Configuration endpoint.

        :param context: The current context
        :type context: Context

        :return: The entity configuration
        :rtype: Response
        """

        if context.qs_params.get('format', '') == 'json':
            return Response(
                json.dumps(self.entity_configuration_as_dict),
                status="200",
                content="application/json"
            )

        return Response(
            self.entity_configuration,
            status="200",
            content="application/entity-statement+jwt"
        )

    def update_trust_anchors(self):
        """
        Updates the trust anchors of current instance.
        """

        tas = self.config['trust']['federation']['config']['trust_anchors']
        self._log_info("Trust Anchors updates", f"Trying to update: {tas}")

        for ta in tas:
            try:
                update_trust_anchors_ecs(
                    db=self.db_engine,
                    trust_anchors=[ta],
                    httpc_params=self.config['network']['httpc_params']
                )
            except Exception as e:
                self._log_warning("Trust Anchor updates",
                                  f"{ta} update failed: {e}")

            self._log_info("Trust Anchor updates", f"{ta} updated")

    def get_backend_trust_chain(self) -> list[str]:
        """
        Get the backend trust chain. In case something raises an Exception (e.g. faulty storage), logs a warning message
        and returns an empty list.

        :return: The trust chain
        :rtype: list
        """
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
            message = (
                f"Error while building trust chain for client with id: {self.client_id}. "
                f"{e.__class__.__name__}: {e}"
            )
            self._log_warning("Trust Chain", message)

        return []

    def _validate_trust(self, context: Context, jws: str) -> TrustEvaluationHelper:
        """
        Validates the trust of the given jws.

        :param context: the request context
        :type context: satosa.context.Context
        :param jws: the jws to validate
        :type jws: str

        :raises: NotTrustedFederationError: raises an error if the trust evaluation fails.

        :return: the trust evaluation helper
        :rtype: TrustEvaluationHelper
        """

        self._log_debug(context, "[TRUST EVALUATION] evaluating trust.")

        headers = decode_jwt_header(jws)
        trust_eval = TrustEvaluationHelper(
            self.db_engine,
            httpc_params=self.config['network']['httpc_params'],
            **headers
        )

        try:
            trust_eval.evaluation_method()
        except EntryNotFound:
            message = (
                "[TRUST EVALUATION] not found for "
                f"{trust_eval.entity_id}"
            )
            self._log_error(context, message)
            raise NotTrustedFederationError(
                f"{trust_eval.entity_id} not found for Trust evaluation."
            )
        except Exception as e:
            message = (
                "[TRUST EVALUATION] failed for "
                f"{trust_eval.entity_id}: {e}"
            )
            self._log_error(context, message)
            raise NotTrustedFederationError(
                f"{trust_eval.entity_id} is not trusted."
            )

        return trust_eval
