import logging
from pyeudiw.tools.utils import iat_now
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_payload, decode_jwt_header
from pyeudiw.federation import is_es
from pyeudiw.federation.policy import TrustChainPolicy
from pyeudiw.federation.statements import (
    get_entity_configurations,
    get_entity_statements
)
from pyeudiw.federation.exceptions import (
    MissingTrustAnchorPublicKey,
    TimeValidationError,
    KeyValidationError,
    InvalidEntityStatement
)

from pyeudiw.jwk import find_jwk
from pyeudiw.jwk.exceptions import KidNotFoundError, InvalidKid

logger = logging.getLogger(__name__)


class StaticTrustChainValidator:
    """Helper class for Static Trust Chain validation"""

    def __init__(
        self,
        static_trust_chain: list[str],
        trust_anchor_jwks: list[dict],
        httpc_params: dict,
        **kwargs,
    ) -> None:
        """
        Generates a new StaticTrustChainValidator istance

        :param static_trust_chain: the list of JWTs, containing the EC, componing the static tust chain
        :type static_trust_chain: list[str]
        :param trust_anchor_jwks: the list of trust anchor jwks
        :type trust_anchor_jwks: list[dict]
        :param httpc_params: parameters to perform http requests
        :type httpc_params: dict
        """

        self.static_trust_chain = static_trust_chain
        self.updated_trust_chain = []
        self.exp = 0
        self.httpc_params = httpc_params

        if not trust_anchor_jwks:
            raise MissingTrustAnchorPublicKey(
                f"{self.__class__.__name__} cannot "
                "created without the TA public jwks"
            )

        self.trust_anchor_jwks = trust_anchor_jwks
        for k, v in kwargs.items():
            setattr(self, k, v)

    def _check_expired(self, exp: int) -> bool:
        """
        Checks if exp value is expired.

        :param exp: an integer that represent the timestemp to check
        :type exp: int
        :returns: True if exp is expired and False otherwise
        :rtype: bool
        """

        return exp < iat_now()

    def _validate_exp(self, exp: int) -> None:
        """
        Checks if exp value is expired.

        :param exp: an integer that represent the timestemp to check
        :type exp: int

        :raises TimeValidationError: if exp value is expired
        """

        if not self._check_expired(exp):
            raise TimeValidationError(
                "Expired validation error"
            )

    def _validate_keys(self, fed_jwks: list[dict], st_header: dict) -> None:
        """
        Checks that the kid in st_header match with one JWK present
        in the federation JWKs list.

        :param fed_jwks: the list of federation's JWKs
        :type fed_jwks: list[dict]
        :param st_header: the statement header
        :type st_header: dict

        :raises KeyValidationError: if no JWK with the kid specified in feild st_header is found
        """

        current_kid = st_header["kid"]

        validation_kid = None

        for key in fed_jwks:
            if key["kid"] == current_kid:
                validation_kid = key

        if not validation_kid:
            raise KeyValidationError(f"Kid {current_kid} not found")

    def validate(self) -> bool:
        """
        Validates the static chain checking the validity in all jwt inside the field trust_chain.

        :returns: True if static chain is valid and False otherwise
        :rtype: bool
        """

        # start from the last entity statement
        rev_tc = [
            i for i in reversed(self.trust_chain)
        ]

        # inspect the entity statement kid header to know which
        # TA's public key to use for the validation
        last_element = rev_tc[0]
        es_header = decode_jwt_header(last_element)
        es_payload = decode_jwt_payload(last_element)

        ta_jwk = find_jwk(
            es_header.get("kid", None), self.trust_anchor_jwks
        )

        if not ta_jwk:
            logger.error(
                "Trust chain validation error: TA jwks not found."
            )
            return False

        # Validate the last statement with ta_jwk
        jwsh = JWSHelper(ta_jwk)

        if not jwsh.verify(last_element):
            logger.error(
                f"Trust chain signature validation error: {last_element} using {ta_jwk}"
            )
            return False

        # then go ahead with other checks
        self.exp = es_payload["exp"]

        if self._check_expired(self.exp):
            logger.error(
                f"Trust chain validation error, statement expired: {es_payload}"
            )
            return False

        fed_jwks = es_payload["jwks"]["keys"]

        # for st in rev_tc[1:]:
        # validate the entire chain taking in cascade using fed_jwks
        # if valid -> update fed_jwks with $st
        for st in rev_tc[1:]:
            st_header = decode_jwt_header(st)
            st_payload = decode_jwt_payload(st)

            try:
                jwk = find_jwk(
                    st_header.get("kid", None), fed_jwks
                )
            except (KidNotFoundError, InvalidKid):
                logger.error(
                    f"Trust chain validation KidNotFoundError: {st_header} not in {fed_jwks}"
                )
                return False

            jwsh = JWSHelper(jwk)
            if not jwsh.verify(st):
                logger.error(
                    f"Trust chain signature validation error: {st} using {jwk}"
                )
                return False
            else:
                fed_jwks = st_payload["jwks"]["keys"]

            self.set_exp(st_payload["exp"])

        return True

    def _retrieve_ec(self, iss: str) -> str:
        """
        Retrieves the Entity configuration from an on-line source.

        :param iss: The issuer url where retrieve the entity configuration.
        :type iss: str

        :returns: the entity configuration in form of JWT.
        :rtype: str
        """
        jwt = get_entity_configurations(iss, self.httpc_params)
        return jwt[0]

    def _retrieve_es(self, download_url: str, iss: str) -> str:
        """
        Retrieves the Entity Statement from an on-line source.

        :param download_url: The path where retrieve the entity configuration.
        :type download_url: str
        :param iss: The issuer url.
        :type iss: str

        :returns: the entity statement in form of JWT.
        :rtype: str
        """
        jwt = get_entity_statements(download_url, self.httpc_params)
        return jwt[0]

    def _update_st(self, st: str) -> str:
        """
        Updates the statement retrieving the new one using the source_endpoint and the sub fields of the entity statement payload.

        :param st: The statement in form of a JWT.
        :type st: str

        :returns: the entity statement in form of JWT.
        :rtype: str
        """
        payload = decode_jwt_payload(st)
        iss = payload['iss']

        try:
            is_es(payload)
            # It's an entity configuration
        except InvalidEntityStatement:
            return self._retrieve_ec(iss)

        # if it has the source_endpoint let's try a fast renewal
        download_url: str = payload.get("source_endpoint", "")
        if download_url:
            jwt = self._retrieve_es(
                f"{download_url}?sub={payload['sub']}", iss
            )
        else:
            ec = self._retrieve_ec(iss)
            ec_data = decode_jwt_payload(ec)
            fetch_api_url = None

            try:
                # get superior fetch url
                fetch_api_url = ec_data["metadata"]["federation_entity"][
                    "federation_fetch_endpoint"
                ]
            except KeyError:
                logger.warning(
                    "Missing federation_fetch_endpoint in  "
                    f"federation_entity metadata for {ec_data['sub']}"
                )

            jwt = self._retrieve_es(fetch_api_url, iss)

        return jwt

    def set_exp(self, exp: int) -> None:
        """
        Updates the self.exp field if the exp parameter is more recent than the previous one.

        :param exp: an integer that represent the timestemp to check
        :type exp: int
        """
        if not self.exp or self.exp > exp:
            self.exp = exp

    def update(self) -> bool:
        """
        Updates the statement retrieving and the exp filed and determines the validity of it.

        :returns: True if the updated chain is valid, False otherwise.
        :rtype: bool
        """
        self.exp = 0
        for st in self.static_trust_chain:
            jwt = self._update_st(st)

            exp = decode_jwt_payload(jwt)["exp"]
            self.set_exp(exp)

            self.updated_trust_chain.append(jwt)

        return self.is_valid

    @property
    def is_valid(self) -> bool:
        """Get the validity of chain."""
        return self.validate()

    @property
    def trust_chain(self) -> list[str]:
        """Get the list of the jwt that compones the trust chain."""
        return self.updated_trust_chain or self.static_trust_chain

    @property
    def is_expired(self) -> int:
        """Get the status of chain expiration."""
        return self._check_expired(self.exp)

    @property
    def entity_id(self) -> str:
        """Get the chain's entity_id."""
        chain = self.trust_chain
        payload = decode_jwt_payload(chain[0])
        return payload["iss"]

    @property
    def final_metadata(self) -> dict:
        """Apply the metadata and returns the final metadata."""
        anchor = self.static_trust_chain[-1]
        es_anchor_payload = decode_jwt_payload(anchor)

        policy = es_anchor_payload.get("metadata_policy", {})

        leaf = self.static_trust_chain[0]
        es_leaf_payload = decode_jwt_payload(leaf)

        return TrustChainPolicy().apply_policy(es_leaf_payload["metadata"], policy)
