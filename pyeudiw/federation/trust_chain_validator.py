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

logger = logging.getLogger("pyeudiw.federation")


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
        **kwargs,
    ) -> None:

        self.static_trust_chain = static_trust_chain
        self.updated_trust_chain = []

        if not trust_anchor_jwks:
            raise MissingTrustAnchorPublicKey(
                f"{self.__class__.__name__} cannot "
                "created without the TA public jwks"
            )

        self.trust_anchor_jwks = trust_anchor_jwks
        for k, v in kwargs.items():
            setattr(self, k, v)

    def is_expired(self, exp):
        return exp < iat_now()

    def _validate_keys(self, fed_jwks, st_header):
        current_kid = st_header["kid"]

        validation_kid = None

        for key in fed_jwks:
            if key["kid"] == current_kid:
                validation_kid = key

        if not validation_kid:
            raise KeyValidationError(f"Kid {current_kid} not found")

    def _validate_single(self, fed_jwks, header, payload):
        try:
            self._validate_keys(fed_jwks, header)
            self._validate_exp(payload["exp"])
        except Exception as e:
            logger.warning(f"Warning: {e}")
            return False

        return True

    @property
    def is_valid(self):
        # start from the last entity statement
        rev_tc = [
            i for i in reversed(
                self.updated_trust_chain or self.static_trust_chain
            )
        ]

        # inspect the entity statement kid header to know which
        # TA's public key to use for the validation

        last_element = rev_tc[0]
        es_header = unpad_jwt_header(last_element)
        es_payload = unpad_jwt_payload(last_element)
        ta_jwk = find_jwk(
            es_header.get("kid", None), self.trust_anchor_jwks
        )

        # Validate the last statement with ta_jwk
        jwsh = JWSHelper(ta_jwk)

        if not jwsh.verify(last_element):
            return False

        # then go ahead with other checks
        es_exp = es_payload["exp"]

        iat_now() - es_exp
        if self.is_expired(es_exp):
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

    def _retrieve_ec(self, iss: str, httpc_params: dict = {}):
        jwt = get_entity_configurations(iss, httpc_params)
        if len(jwt) == 0:
            raise HttpError(
                f"Cannot get the Entity Configuration from {iss}")

        # is something weird these will raise their Exceptions
        return jwt[0]

    def _retrieve_es(self, download_url: str, iss: str, httpc_params: dict = {}):
        jwt = get_entity_statements(download_url, httpc_params)
        if not jwt:
            logger.warning(
                f"Cannot fast refresh Entity Statement {iss}"
            )
        return jwt

    def _update_st(self, st, httpc_params: dict = {}):
        payload = unpad_jwt_payload(st)
        iss = payload['iss']

        if not is_es(payload):
            # It's an entity configuration
            return self._retrieve_ec(iss, httpc_params)

        # if it has the source_endpoint let's try a fast renewal
        download_url: str = payload.get("source_endpoint", "")
        if download_url:
            jwt = self._retrieve_es(download_url, iss, httpc_params)
        else:
            ec = self._retrieve_ec(iss, httpc_params)
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

            jwt = self._retrieve_es(fetch_api_url, iss, httpc_params)

        return jwt

    def update(self, httpc_params: dict = {}):
        for st in self.static_trust_chain:
            jwt = self._update_st(st, httpc_params)
            self.updated_trust_chain.append(jwt)

        return self.is_valid
