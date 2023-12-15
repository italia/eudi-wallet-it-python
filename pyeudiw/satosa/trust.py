import json
import satosa.logging_util as lu
from satosa.context import Context
from satosa.response import Response

from pyeudiw.jwk import JWK
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header
from pyeudiw.satosa.exceptions import (
    NotTrustedFederationError, DiscoveryFailedError
)
from pyeudiw.tools.utils import iat_now, exp_from_now
from pyeudiw.storage.exceptions import EntryNotFound
from pyeudiw.trust import TrustEvaluationHelper
from pyeudiw.trust.trust_anchors import update_trust_anchors_ecs

from .base_logger import BaseLogger

class BackendTrust(BaseLogger):
    """
    Backend Trust class.
    """

    def init_trust_resources(self) -> None:
        """
        Initializes the trust resources.
        """

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
            self.get_backend_trust_chain()
        except Exception as e:
            self._log_critical("Backend Trust", f"Cannot fetch the trust anchor configuration: {e}")

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
        """
        Updates the trust anchors of current instance.
        """

        tas = self.config['federation']['trust_anchors']
        self._log_info("Trust Anchors updates", f"Trying to update: {tas}")
        
        for ta in tas:
            try:
                update_trust_anchors_ecs(
                    db=self.db_engine,
                    trust_anchors=[ta],
                    httpc_params=self.config['network']['httpc_params']
                )
            except Exception as e:
                self._log_warning("Trust Anchor updates", f"{ta} update failed: {e}")

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
                f"Error while building trust chain for client with id: {self.client_id}\n"
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

    
    @property
    def default_federation_private_jwk(self) -> dict:
        """Returns the default federation private jwk."""
        return tuple(self.federations_jwks_by_kids.values())[0]

    @property
    def entity_configuration_as_dict(self) -> dict:
        """Returns the entity configuration as a dictionary."""
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
        """Returns the entity configuration as a JWT."""
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