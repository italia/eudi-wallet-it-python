from __future__ import annotations

import logging
from copy import deepcopy

import pydantic

from pyeudiw.federation.exceptions import (InvalidEntityHeader,
                                           InvalidEntityStatementPayload,
                                           MissingJwksClaim, MissingTrustMark,
                                           TrustAnchorNeeded, UnknownKid)
from pyeudiw.federation.schemas.entity_configuration import (
    EntityConfigurationHeader, EntityStatementPayload)
from pyeudiw.jwk import find_jwk_by_kid
from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.tools.utils import get_http_url

OIDCFED_FEDERATION_WELLKNOWN_URL = ".well-known/openid-federation"
logger = logging.getLogger(__name__)


def jwks_from_jwks_uri(jwks_uri: str, httpc_params: dict, http_async: bool = True) -> list[dict]:
    """
    Retrieves jwks from an entity uri.

    :param jwks_uri: the uri where the jwks are located.
    :type jwks_uri: str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param http_async: if is set to True the operation will be performed in async (deafault True)
    :type http_async: bool

    :returns: A list of entity jwks.
    :rtype: list[dict]
    """

    response = get_http_url(jwks_uri, httpc_params, http_async)
    jwks = [i.json() for i in response]

    return jwks


def get_federation_jwks(jwt_payload: dict) -> list[dict]:
    """
    Returns the list of JWKS inside a JWT payload.

    :param jwt_payload: the jwt payload from where extract the JWKs.
    :type jwt_payload: dict

    :returns: A list of entity jwk's keys.
    :rtype: list[dict]
    """

    jwks = jwt_payload.get("jwks", {})
    keys = jwks.get("keys", [])
    return keys


def get_entity_statements(urls: list[str] | str, httpc_params: dict, http_async: bool = True) -> list[bytes]:
    """
    Fetches an entity statement from the specified urls.

    :param urls: The url or a list of url where perform the GET HTTP calls
    :type urls: list[str] | str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param http_async: if is set to True the operation will be performed in async (deafault True)
    :type http_async: bool

    :returns: A list of entity statements.
    :rtype: list[Response]
    """

    urls = urls if isinstance(urls, list) else [urls]
    for url in urls:
        logger.debug(f"Starting Entity Statement Request to {url}")

    return [
        i.content for i in
        get_http_url(urls, httpc_params, http_async)
    ]


def get_entity_configurations(subjects: list[str] | str, httpc_params: dict, http_async: bool = False) -> list[bytes]:
    """
    Fetches an entity configuration from the specified subjects.

    :param subjects: The url or a list of url where perform the GET HTTP calls
    :type subjects: list[str] | str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param http_async: if is set to True the operation will be performed in async (deafault True)
    :type http_async: bool

    :returns: A list of entity statements.
    :rtype: list[Response]
    """

    subjects = subjects if isinstance(subjects, list) else [subjects]

    urls = []
    for subject in subjects:
        if subject[-1] != "/":
            subject = f"{subject}/"
        url = f"{subject}{OIDCFED_FEDERATION_WELLKNOWN_URL}"
        urls.append(url)
        logger.info(f"Starting Entity Configuration Request for {url}")

    return [
        i.content for i in
        get_http_url(urls, httpc_params, http_async)
    ]


class TrustMark:
    """The class representing a Trust Mark"""

    def __init__(self, jwt: str, httpc_params: dict):
        """
        Create an instance of Trust Mark

        :param jwt: the JWT containing the trust marks
        :type jwt: str
        :param httpc_params: parameters to perform http requests.
        :type httpc_params: dict
        """

        self.jwt = jwt
        self.header = decode_jwt_header(jwt)
        self.payload = decode_jwt_payload(jwt)

        self.id = self.payload["id"]
        self.sub = self.payload["sub"]
        self.iss = self.payload["iss"]

        self.is_valid = False

        self.issuer_entity_configuration: list[bytes] = None
        self.httpc_params = httpc_params

    def validate_by(self, ec: dict) -> bool:
        """
        Validates Trust Marks by an Entity Configuration

        :param ec: the entity configuration to validate by
        :type ec: dict

        :returns: True if is valid otherwise False
        :rtype: bool
        """
        try:
            EntityConfigurationHeader(**self.header)
        except pydantic.ValidationError as e:
            raise InvalidEntityHeader(
                # pragma: no cover
                f"Trust Mark validation failed: "
                f"{e}"
            )

        _kid = self.header["kid"]

        if _kid not in ec.kids:
            raise UnknownKid(  # pragma: no cover
                f"Trust Mark validation failed: "
                f"{self.header.get('kid')} not found in {ec.jwks}"
            )

        _jwk = find_jwk_by_kid(_kid, ec.jwks)

        # verify signature
        jwsh = JWSHelper(_jwk)
        payload = jwsh.verify(self.jwt)
        self.is_valid = True
        return payload

    def validate_by_its_issuer(self) -> bool:
        """
        Validates Trust Marks by it's issuer

        :returns: True if is valid otherwise False
        :rtype: bool
        """
        if not self.issuer_entity_configuration:
            self.issuer_entity_configuration = [
                i.content for i in
                get_entity_configurations(
                    self.iss, self.httpc_params, False
                )
            ]

        _kid = self.header.get('kid')
        try:
            ec = EntityStatement(self.issuer_entity_configuration[0])
            ec.validate_by_itself()
        except UnknownKid:
            logger.warning(
                f"Trust Mark validation failed by its Issuer: "
                f"{_kid} not found in "
                f"{self.issuer_entity_configuration.jwks}")
            return False
        except Exception:
            logger.warning(
                f"Issuer {self.iss} of trust mark {self.id} is not valid.")
            self.is_valid = False
            return False

        # verify signature
        _jwk = find_jwk_by_kid(_kid, ec.jwks)
        jwsh = JWSHelper(_jwk)
        payload = jwsh.verify(self.jwt)
        self.is_valid = True
        return payload

    def __repr__(self) -> str:
        return f"{self.id} to {self.sub} issued by {self.iss}"


class EntityStatement:
    """
    The self issued/signed statement of a federation entity
    """

    def __init__(
        self,
        jwt: str,
        httpc_params: dict,
        filter_by_allowed_trust_marks: list[str] = [],
        trust_anchor_entity_conf: EntityStatement | None = None,
        trust_mark_issuers_entity_confs: list[EntityStatement] = [],
    ):
        """
        Creates EntityStatement istance

        :param jwt: the JWT containing the trust marks.
        :type jwt: str
        :param httpc_params: parameters to perform http requests.
        :type httpc_params: dict
        :param filter_by_allowed_trust_marks: allowed trust marks list.
        :type filter_by_allowed_trust_marks: list[str]
        :param trust_anchor_entity_conf: the trust anchor entity conf or None
        :type trust_anchor_entity_conf: EntityStatement | None
        :param trust_mark_issuers_entity_confs: the list containig the trust mark's entiity confs
        """
        self.jwt = jwt
        self.header = decode_jwt_header(jwt)
        self.payload = decode_jwt_payload(jwt)
        self.sub = self.payload["sub"]
        self.iss = self.payload["iss"]
        self.exp = self.payload["exp"]
        self.jwks = get_federation_jwks(self.payload)
        if not self.jwks or not self.jwks[0]:
            _msg = f"Missing jwks in the statement for {self.sub}"
            logger.error(_msg)
            raise MissingJwksClaim(_msg)

        self.kids = [i.get("kid") for i in self.jwks]
        self.httpc_params = httpc_params

        self.filter_by_allowed_trust_marks = filter_by_allowed_trust_marks
        self.trust_anchor_entity_conf = trust_anchor_entity_conf
        self.trust_mark_issuers_entity_confs = trust_mark_issuers_entity_confs

        # a dict with sup_sub : superior entity configuration
        self.verified_superiors = {}
        # as previous but with superiors with invalid entity configurations
        self.failed_superiors = {}

        # a dict with sup_sub : entity statement issued for self
        self.verified_by_superiors = {}
        self.failed_by_superiors = {}

        # a dict with the paylaod of valid entity statements for each descendant subject
        self.verified_descendant_statements = {}
        self.failed_descendant_statements = {}

        # a dict with the RAW JWT of valid entity statements for each descendant subject
        self.verified_descendant_statements_as_jwt = {}

        self.verified_trust_marks = []
        self.is_valid = False

    def update_trust_anchor_conf(self, trust_anchor_entity_conf: 'EntityStatement') -> None:
        """
        Updates the internal Trust Anchor conf.

        :param trust_anchor_entity_conf: the trust anchor entity conf
        :type trust_anchor_entity_conf: EntityStatement
        """
        self.trust_anchor_entity_conf = trust_anchor_entity_conf

    def validate_by_itself(self) -> bool:
        """
        validates the entity configuration by it self
        """
        try:
            EntityConfigurationHeader(**self.header)
        except pydantic.ValidationError as e:
            raise InvalidEntityHeader(
                # pragma: no cover
                f"Trust Mark validation failed: "
                f"{e}"
            )

        _kid = self.header.get("kid")

        if _kid not in self.kids:
            raise UnknownKid(
                f"{_kid} not found in {self.jwks}")  # pragma: no cover

        # verify signature
        _jwk = find_jwk_by_kid(_kid, self.jwks)
        jwsh = JWSHelper(_jwk)
        jwsh.verify(self.jwt)
        self.is_valid = True
        return True

    def validate_by_allowed_trust_marks(self) -> bool:
        """
        validate the entity configuration ony if marked by a well known
        trust mark, issued by a trusted issuer
        """

        if not self.trust_anchor_entity_conf:
            raise TrustAnchorNeeded(
                "To validate the trust marks the "
                "Trust Anchor Entity Configuration "
                "is needed."
            )

        if not self.filter_by_allowed_trust_marks:
            return True

        if not self.payload.get("trust_marks"):
            logger.warning(
                f"{self.sub} doesn't have the trust marks claim "
                "in its Entity Configuration"
            )
            return False

        trust_marks = []
        is_valid = False
        for tm in self.payload["trust_marks"]:

            if tm.get("id", None) not in self.filter_by_allowed_trust_marks:
                continue

            try:
                trust_mark = TrustMark(tm["trust_mark"])
            except KeyError:
                logger.warning(
                    f"Trust Mark decoding failed on [{tm}]. "
                    "Missing 'trust_mark' claim in it"
                )
            except Exception:
                logger.warning(f"Trust Mark decoding failed on [{tm}]")
                continue
            else:
                trust_marks.append(trust_mark)

        if not trust_marks:
            raise MissingTrustMark(
                "Required Trust marks are missing.")  # pragma: no cover

        trust_mark_issuers_by_id = self.trust_anchor_entity_conf.payload.get(
            "trust_marks_issuers", {}
        )

        # TODO : cache of issuers -> it would be better to have a proxy function
        #
        # required_issuer_ecs = []
        # for trust_mark in trust_marks:
        # if trust_mark.iss not in [
        # i.payload.get('iss', None)
        # for i in self.trust_mark_issuers_entity_confs
        # ]:
        # required_issuer_ecs.append(trust_mark.iss)
        # TODO: snippet for CACHE
        # if required_issuer_ec:
        # ## fetch the issuer entity configuration and validate it
        # iecs = get_entity_configurations(
        # [required_issuer_ecs], self.httpc_params
        # )
        # for jwt in iecs:
        # try:
        # ec = self.__class__(jwt, httpc_params=self.httpc_params)
        # ec.validate_by_itself()
        # except Exception as e:
        # logger.warning(
        # "Trust Marks issuer Entity Configuration "
        # f"failed for {jwt}: {e}"
        # )
        # continue
        # self.trust_mark_issuers_entity_confs.append(ec)

        for trust_mark in trust_marks:
            id_issuers = trust_mark_issuers_by_id.get(trust_mark.id, None)
            if id_issuers and trust_mark.iss not in id_issuers:
                is_valid = False
            elif id_issuers and trust_mark.iss in id_issuers:
                is_valid = trust_mark.validate_by_its_issuer()
            elif not id_issuers:
                is_valid = trust_mark.validate_by(
                    self.trust_anchor_entity_conf)

            if not trust_mark.is_valid:
                is_valid = False

            if is_valid:
                logger.info(f"Trust Mark {trust_mark} is valid")
                self.verified_trust_marks.append(trust_mark)
            else:
                logger.warning(f"Trust Mark {trust_mark} is not valid")

        return is_valid

    def get_superiors(
        self,
        authority_hints: list[str] = [],
        max_authority_hints: int = 0,
        superiors_hints: list[dict] = [],
    ) -> dict:
        """
        get superiors entity configurations

        :param authority_hints: the authority hint list
        :type authority_hints: list[str]
        :param max_authority_hints: the number of max authority hint
        :type max_authority_hints: int
        :param superiors_hints: the list of superior hints
        :type superiors_hints: list[dict]

        :returns: a dict with the superior's entity configurations
        :rtype: dict
        """
        # apply limits if defined
        authority_hints = authority_hints or deepcopy(
            self.payload.get("authority_hints", []))
        if (
            max_authority_hints
            and authority_hints != authority_hints[:max_authority_hints]
        ):
            logger.warning(
                f"Found {len(authority_hints)} but "
                f"authority maximum hints is set to {max_authority_hints}. "
                "the following authorities will be ignored: "
                f"{', '.join(authority_hints[max_authority_hints:])}"
            )
            authority_hints = authority_hints[:max_authority_hints]

        for sup in superiors_hints:
            if sup.sub in authority_hints:
                logger.info(
                    "Getting Cached Entity Configurations for "
                    f"{[i.sub for i in superiors_hints]}"
                )
                authority_hints.pop(authority_hints.index(sup.sub))
                self.verified_superiors[sup.sub] = sup

        logger.debug(f"Getting Entity Configurations for {authority_hints}")

        jwts = []

        if self.trust_anchor_entity_conf:
            ta_id = self.trust_anchor_entity_conf.payload.get("sub", {})
            if ta_id in authority_hints:
                jwts = [self.trust_anchor_configuration]

        if not jwts:
            jwts = get_entity_configurations(
                authority_hints, self.httpc_params, False
            )

        for jwt in jwts:
            try:
                ec = self.__class__(
                    jwt,
                    httpc_params=self.httpc_params,
                    trust_anchor_entity_conf=self.trust_anchor_entity_conf
                )
            except Exception as e:
                logger.warning(f"Get Entity Configuration for {jwt}: {e}")
                continue

            if ec.validate_by_itself():
                target = self.verified_superiors
            else:
                target = self.failed_superiors

            target[ec.payload["sub"]] = ec

        for ahints in authority_hints:
            if not self.verified_superiors.get(ahints, None):
                logger.warning(
                    f"{ahints} is not available, missing or not valid authority hint"
                )
                continue

        return self.verified_superiors

    def validate_descendant_statement(self, jwt: str) -> bool:
        """
        jwt is a descendant entity statement issued by self

        :param jwt: the JWT to validate by
        :type jwt: str

        :returns: True if is valid or False otherwise
        :rtype: bool
        """
        header = decode_jwt_header(jwt)
        payload = decode_jwt_payload(jwt)

        try:
            EntityConfigurationHeader(**header)
        except pydantic.ValidationError as e:
            raise InvalidEntityHeader(  # pragma: no cover
                f"Trust Mark validation failed: "
                f"{e}"
            )

        try:
            EntityStatementPayload(**payload)
        except pydantic.ValidationError as e:
            raise InvalidEntityStatementPayload(  # pragma: no cover
                f"Trust Mark validation failed: "
                f"{e}"
            )

        _kid = header.get("kid")

        if _kid not in self.kids:
            raise UnknownKid(
                f"{_kid} not found in {self.jwks}")

        # verify signature
        _jwk = find_jwk_by_kid(_kid, self.jwks)
        jwsh = JWSHelper(_jwk)
        payload = jwsh.verify(jwt)

        self.verified_descendant_statements[payload["sub"]] = payload
        self.verified_descendant_statements_as_jwt[payload["sub"]] = jwt
        return self.verified_descendant_statements

    def validate_by_superior_statement(self, jwt: str, ec: 'EntityStatement') -> str:
        """
        validates self with the jwks contained in statement of the superior
        :param jwt: the statement issued by a superior in form of JWT
        :type jwt: str
        :param ec: is a superior entity configuration
        :type ec: EntityStatement

        :returns: the entity configuration subject if is valid
        :rtype: str
        """
        is_valid = None
        payload = {}
        try:
            payload = decode_jwt_payload(jwt)
            ec.validate_by_itself()
            ec.validate_descendant_statement(jwt)
            _jwks = get_federation_jwks(payload)
            _jwk = find_jwk_by_kid(self.header["kid"], _jwks)

            jwsh = JWSHelper(_jwk)
            payload = jwsh.verify(self.jwt)

            is_valid = True
        except Exception as e:
            logger.warning(
                f"{self.sub} failed validation with "
                f"{ec.sub}'s superior statement '{payload or jwt}'. "
                f"Exception: {e}"
            )
            is_valid = False

        if is_valid:
            target = self.verified_by_superiors
            ec.verified_descendant_statements[self.sub] = payload
            ec.verified_descendant_statements_as_jwt[self.sub] = jwt
            target[payload["iss"]] = ec
            self.is_valid = True
            return self.verified_by_superiors.get(ec.sub)
        else:
            target = self.failed_superiors
            ec.failed_descendant_statements[self.sub] = payload
            self.is_valid = False

    def validate_by_superiors(
        self,
        superiors_entity_configurations: dict = {},
    ) -> dict:
        """
        validates the entity configuration with the entity statements issued by its superiors
        this methods create self.verified_superiors and failed ones and self.verified_by_superiors and failed ones

        :param superiors_entity_configurations: an object containing the entity configurations of superiors
        :type superiors_entity_configurations: dict

        :returns: an object containing the superior validations
        :rtype: dict
        """
        for ec in superiors_entity_configurations:
            if ec.sub in ec.verified_by_superiors:
                # already fetched and cached
                continue

            try:
                # get superior fetch url
                fetch_api_url = ec.payload["metadata"]["federation_entity"][
                    "federation_fetch_endpoint"
                ]
            except KeyError:
                logger.warning(
                    "Missing federation_fetch_endpoint in  "
                    f"federation_entity metadata for {self.sub} by {ec.sub}."
                )
                self.failed_superiors[ec.sub] = None
                continue

            else:
                _url = f"{fetch_api_url}?sub={self.sub}"
                logger.info(f"Getting entity statements from {_url}")
                jwts = get_entity_statements([_url], self.httpc_params, False)
                if not jwts:
                    logger.error(
                        f"Empty response for {_url}"
                    )
                jwt = jwts[0]
                if jwt:
                    self.validate_by_superior_statement(jwt, ec)
                else:
                    logger.error(
                        f"JWT validation for {_url}"
                    )

        return self.verified_by_superiors

    def __repr__(self) -> str:
        return f"{self.sub} valid {self.is_valid}"
