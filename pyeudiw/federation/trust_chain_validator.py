import logging
from pyeudiw.tools.utils import iat_now
from pyeudiw.jwt import JWSHelper
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header
from pyeudiw.federation.schema import is_es
from pyeudiw.federation.statements import (
    get_entity_configurations,
    get_entity_statements
)
from pyeudiw.federation.exceptions import (
    HttpError,
    MissingTrustAnchorPublicKey,
    TimeValidationError,
    KeyValidationError
)

logger = logging.getLogger(__name__)


def find_jwk(kid: str, jwks: list) -> dict:
    if not kid:
        return {}
    for jwk in jwks:
        valid_jwk = jwk.get("kid", None)
        if valid_jwk and kid == valid_jwk:
            return jwk


class StaticTrustChainValidator:
    def __init__(
        self,
        static_trust_chain: list,
        trust_anchor_jwks: list,
        httpc_params: dict,
        **kwargs,
    ) -> None:

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
        return exp < iat_now()

    def _validate_keys(self, fed_jwks: list[str], st_header: dict) -> None:
        current_kid = st_header["kid"]

        validation_kid = None

        for key in fed_jwks:
            if key["kid"] == current_kid:
                validation_kid = key

        if not validation_kid:
            raise KeyValidationError(f"Kid {current_kid} not found")

    def _validate_single(self, fed_jwks: list[str], header: dict, payload: dict) -> bool:
        try:
            self._validate_keys(fed_jwks, header)
            self._validate_exp(payload["exp"])
        except Exception as e:
            logger.warning(f"Warning: {e}")
            return False

        return True

    @property
    def is_valid(self) -> bool:
        # start from the last entity statement
        rev_tc = [
            i for i in reversed(self.get_chain())
        ]
        # inspect the entity statement kid header to know which
        # TA's public key to use for the validation

        last_element = rev_tc[0]
        es_header = unpad_jwt_header(last_element)
        es_payload = unpad_jwt_payload(last_element)

        ta_jwk = find_jwk(
            es_header.get("kid", None), self.trust_anchor_jwks
        )

        if not ta_jwk:
            return False

        # Validate the last statement with ta_jwk
        jwsh = JWSHelper(ta_jwk)

        if not jwsh.verify(last_element):
            return False

        # then go ahead with other checks
        es_exp = es_payload["exp"]

        if self._check_expired(es_exp):
            raise TimeValidationError()

        fed_jwks = es_payload["jwks"]["keys"]

        # for st in rev_tc[1:]:
        # validate the entire chain taking in cascade using fed_jwks
        # if valid -> update fed_jwks with $st
        for st in rev_tc[1:]:
            st_header = unpad_jwt_header(st)
            st_payload = unpad_jwt_payload(st)
            jwk = find_jwk(
                st_header.get("kid", None), fed_jwks
            )

            if not jwk:
                return False

            jwsh = JWSHelper(jwk)
            if not jwsh.verify(st):
                return False
            else:
                fed_jwks = st_payload["jwks"]["keys"]

        return True

    def _retrieve_ec(self, iss: str) -> str:
        jwt = get_entity_configurations(iss, self.httpc_params)
        if not jwt:
            raise HttpError(
                f"Cannot get the Entity Configuration from {iss}")

        # is something weird these will raise their Exceptions
        return jwt[0]

    def _retrieve_es(self, download_url: str, iss: str) -> str:
        jwt = get_entity_statements(download_url, self.httpc_params)
        if not jwt:
            logger.warning(
                f"Cannot fast refresh Entity Statement {iss}"
            )
        return jwt

    def _update_st(self, st: str) -> str:
        payload = unpad_jwt_payload(st)
        iss = payload['iss']

        if not is_es(payload):
            # It's an entity configuration
            return self._retrieve_ec(iss)

        # if it has the source_endpoint let's try a fast renewal
        download_url: str = payload.get("source_endpoint", "")
        if download_url:
            jwt = self._retrieve_es(download_url, iss)
        else:
            ec = self._retrieve_ec(iss)
            ec_data = unpad_jwt_payload(ec)
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

    def update(self) -> bool:
        self.exp = 0
        for st in self.static_trust_chain:
            jwt = self._update_st(st, self.httpc_params)

            exp = unpad_jwt_payload(jwt)["exp"]

            if not self.exp or self.exp > exp:
                self.exp = exp

            self.updated_trust_chain.append(jwt)

        return self.is_valid

    def get_chain(self) -> list[str]:
        return self.updated_trust_chain or self.static_trust_chain

    def get_exp(self) -> int:
        return self.exp

    @property
    def is_expired(self) -> int:
        return self._check_expired(self.exp)

    def get_entityID(self) -> str:
        chain = self.get_chain()
        payload = unpad_jwt_payload(chain[0])
        return payload["iss"]

    # TODO - apply metadata policy and get the final metadata
