import datetime
import json
import logging

from collections import OrderedDict
from typing import Union

from .policy import TrustChainPolicy

from .exceptions import (
    InvalidEntityStatement,
    InvalidRequiredTrustMark,
    MetadataDiscoveryException
)

from .statements import (
    get_entity_configurations,
    EntityStatement,
)
from pyeudiw.tools.utils import datetime_from_timestamp


logger = logging.getLogger(__name__)


class TrustChainBuilder:
    """
    A trust walker that fetches statements and evaluate the evaluables
    """

    def __init__(
        self,
        subject: str,
        trust_anchor: str,
        httpc_params: dict,
        trust_anchor_configuration: Union[EntityStatement, str, None] = None,
        max_authority_hints: int = 10,
        subject_configuration: EntityStatement | None = None,
        required_trust_marks: list[dict] = [],
        # TODO - prefetch cache?
        # pre_fetched_entity_configurations = {},
        # pre_fetched_statements = {},
        #
        **kwargs,
    ) -> None:
        """
        Initialized a TrustChainBuilder istance

        :parameter subject: represents the subject url (leaf) of the Trust Chain
        :type subject: str
        :parameter trust_anchor: represents the issuer url (leaf) of the Trust Chain
        :type trust_anchor: str
        :param httpc_params: parameters needed to perform http requests
        :type httpc_params: dict
        :param trust_anchor_configuration: is the entity statment configuration of Trust Anchor.
        The assigned value can be an EntityStatement, a str or None.
        If the value is a string it will be converted in an EntityStatement istance.
        If the value is None it will be retrieved from an http request on the trust_anchor field.
        :parameter max_authority_hints: the number of how many authority_hints to follow on each hop
        :type max_authority_hints: int
        :parameter subject_configuration: the configuration of subject
        :type subject_configuration: EntityStatement
        :parameter required_trust_marks: means all the trust marks needed to start a metadata discovery
        at least one of the required trust marks is needed to start a metadata discovery
        if this param if absent the filter won't be considered.
        :type required_trust_marks: list[dict]

        """

        self.subject = subject
        self.subject_configuration = subject_configuration
        self.httpc_params = httpc_params

        self.trust_anchor = trust_anchor
        if not trust_anchor_configuration:
            try:
                jwts = get_entity_configurations(
                    trust_anchor, httpc_params=self.httpc_params
                )
                trust_anchor_configuration = EntityStatement(
                    jwts[0], httpc_params=self.httpc_params
                )

                subject_configuration.update_trust_anchor_conf(
                    trust_anchor_configuration)
                subject_configuration.validate_by_itself()
            except Exception as e:
                _msg = f"Entity Configuration for {self.trust_anchor} failed: {e}"
                logger.error(_msg)
                raise InvalidEntityStatement(_msg)
        elif isinstance(trust_anchor_configuration, str):
            trust_anchor_configuration = EntityStatement(
                jwt=trust_anchor_configuration,
                httpc_params=self.httpc_params
            )

        self.trust_anchor_configuration = trust_anchor_configuration

        self.required_trust_marks = required_trust_marks
        self.is_valid = False

        self.tree_of_trust = OrderedDict()
        self.trust_path = []  # list of valid subjects up to trust anchor

        self.max_authority_hints = max_authority_hints
        # dynamically valued
        self.max_path_len = 0
        self.final_metadata: dict = {}

        self.verified_trust_marks = []
        self.exp = 0
        self._set_max_path_len()

    def apply_metadata_policy(self) -> dict:
        """
        filters the trust path from subject to trust anchor
        apply the metadata policies along the path.

        :returns: the final metadata with policy applied
        :rtype: dict
        """
        # find the path of trust
        if not self.trust_path:
            self.trust_path = [self.subject_configuration]
        elif self.trust_path[-1].sub == self.trust_anchor_configuration.sub:
            # ok trust path completed, I just have to return over all the parent calls
            return

        logger.info(
            f"Applying metadata policy for {self.subject} over "
            f"{self.trust_anchor_configuration.sub} starting from "
            f"{self.trust_path[-1]}"
        )
        last_path = self.tree_of_trust[len(self.trust_path) - 1]
        path_found = False
        for ec in last_path:
            for sup_ec in ec.verified_by_superiors.values():
                while len(self.trust_path) - 2 < self.max_path_len:
                    if sup_ec.sub == self.trust_anchor_configuration.sub:
                        self.trust_path.append(sup_ec)
                        path_found = True
                        break
                    if sup_ec.verified_by_superiors:
                        self.trust_path.append(sup_ec)
                        self.apply_metadata_policy()
                    else:
                        logger.info(
                            f"'Cul de sac' in {sup_ec.sub} for {self.subject} "
                            f"to {self.trust_anchor_configuration.sub}"
                        )
                        self.trust_path = [self.subject_configuration]
                        break

        # once I filtered a concrete and unique trust path I can apply the metadata policy
        if path_found:
            logger.info(f"Found a trust path: {self.trust_path}")
            self.final_metadata = self.subject_configuration.payload.get(
                "metadata", {})
            if not self.final_metadata:
                logger.error(
                    f"Missing metadata in {self.subject_configuration.payload['metadata']}"
                )
                return

            for i in range(len(self.trust_path))[::-1]:
                self.trust_path[i - 1].sub
                _pol = (
                    self.trust_path[i]
                    .verified_descendant_statements.get("metadata_policy", {})
                )
                for md_type, md in _pol.items():
                    if not self.final_metadata.get(md_type):
                        continue
                    self.final_metadata[md_type] = TrustChainPolicy().apply_policy(
                        self.final_metadata[md_type], _pol[md_type]
                    )

        # set exp
        self._set_exp()
        return self.final_metadata

    def _set_exp(self) -> None:
        """
        updates the internal exp field with the nearest
        expiraton date found in the trust_path field
        """
        exps = [i.payload["exp"] for i in self.trust_path]
        if exps:
            self.exp = min(exps)

    def discovery(self) -> bool:
        """
        discovers the chain of verified statements
        from the lower up to the trust anchor and updates
        the internal representation of chain.

        :returns: the validity status of the updated chain
        :rtype: bool
        """
        logger.info(
            f"Starting a Walk into Metadata Discovery for {self.subject}")
        self.tree_of_trust[0] = [self.subject_configuration]

        ecs_history = []
        while (len(self.tree_of_trust) - 2) < self.max_path_len:
            last_path_n = list(self.tree_of_trust.keys())[-1]
            last_ecs = self.tree_of_trust[last_path_n]

            sup_ecs = []
            for last_ec in last_ecs:
                # Metadata discovery loop prevention
                if last_ec.sub in ecs_history:
                    logger.warning(
                        f"Metadata discovery loop detection for {last_ec.sub}. "
                        f"Already present in {ecs_history}. "
                        "Discovery blocked for this path."
                    )
                    continue

                try:
                    superiors = last_ec.get_superiors(
                        max_authority_hints=self.max_authority_hints,
                        superiors_hints=[self.trust_anchor_configuration],
                    )
                    validated_by = last_ec.validate_by_superiors(
                        superiors_entity_configurations=superiors.values()
                    )
                    vbv = list(validated_by.values())
                    sup_ecs.extend(vbv)
                    ecs_history.append(last_ec)
                except MetadataDiscoveryException as e:
                    logger.exception(
                        f"Metadata discovery exception for {last_ec.sub}: {e}"
                    )

            if sup_ecs:
                self.tree_of_trust[last_path_n + 1] = sup_ecs
            else:
                break

        last_path = list(self.tree_of_trust.keys())[-1]
        if (
            self.tree_of_trust[0][0].is_valid
            and self.tree_of_trust[last_path][0].is_valid
        ):
            self.is_valid = True
            self.apply_metadata_policy()

        return self.is_valid

    def get_trust_anchor_configuration(self) -> None:
        """
        Download and updates the internal field trust_anchor_configuration
        with the entity statement of trust anchor.
        """
        if not isinstance(self.trust_anchor, EntityStatement):
            logger.info(
                f"Get Trust Anchor Entity Configuration for {self.subject}")
            ta_jwt = get_entity_configurations(
                self.trust_anchor, httpc_params=self.httpc_params
            )[0]
            self.trust_anchor_configuration = EntityStatement(ta_jwt)

        try:
            self.trust_anchor_configuration.validate_by_itself()
        except Exception as e:  # pragma: no cover
            _msg = (
                f"Trust Anchor Entity Configuration failed for "
                f"{self.trust_anchor}: '{e}'"
            )
            logger.error(_msg)
            raise Exception(_msg)

        self._set_max_path_len()

    def _set_max_path_len(self) -> None:
        """
        Sets the internal field max_path_len with the costraint
        found in trust anchor payload
        """
        if self.trust_anchor_configuration.payload.get("constraints", {}).get(
            "max_path_length"
        ):
            self.max_path_len = int(
                self.trust_anchor_configuration.payload["constraints"][
                    "max_path_length"
                ]
            )

    def get_subject_configuration(self) -> None:
        """
        Download and updates the internal field subject_configuration
        with the entity statement of leaf.

        :rtype: None
        """
        if not self.subject_configuration:
            try:
                jwts = get_entity_configurations(
                    self.subject, httpc_params=self.httpc_params
                )
                self.subject_configuration = EntityStatement(
                    jwts[0], trust_anchor_entity_conf=self.trust_anchor_configuration,
                    httpc_params=self.httpc_params
                )
                self.subject_configuration.validate_by_itself()
            except Exception as e:
                _msg = f"Entity Configuration for {self.subject} failed: {e}"
                logger.error(_msg)
                raise InvalidEntityStatement(_msg)

            # Trust Mark filter
            if self.required_trust_marks:
                sc = self.subject_configuration
                sc.filter_by_allowed_trust_marks = self.required_trust_marks

                # TODO: create a proxy function that gets tm issuers ec from
                # a previously populated cache
                # sc.trust_mark_issuers_entity_confs = [
                # trust_mark_issuers_entity_confs
                # ]
                if not sc.validate_by_allowed_trust_marks():
                    raise InvalidRequiredTrustMark(
                        "The required Trust Marks are not valid"
                    )
                else:
                    self.verified_trust_marks.extend(sc.verified_trust_marks)

    def serialize(self) -> str:
        """
        Serializes the chain in JSON format.

        :returns: the serialized chain in JSON format
        :rtype: str
        """
        return json.dumps(self.get_trust_chain())

    def get_trust_chain(self) -> list[str]:
        """
        Retrieves the leaf and the Trust Anchor entity configurations.

        :returns: the list containing the ECs
        :rtype: list[str]
        """
        res = []
        # we keep just the leaf's and TA's EC, all the intermediates EC will be dropped
        ta_ec: str = ""
        for stat in self.trust_path:
            if (self.subject == stat.sub == stat.iss):
                res.append(stat.jwt)
            elif (self.trust_anchor_configuration.sub == stat.sub == stat.iss):
                ta_ec = stat.jwt

            if stat.verified_descendant_statements:
                res.append(
                    # [dict(i) for i in stat.verified_descendant_statements.values()]
                    [i for i in stat.verified_descendant_statements_as_jwt.values()]
                )
        if ta_ec:
            res.append(ta_ec)
        return res

    def start(self):
        """
        Retrieves the subject (leaf) configuration and starts
        chain discovery.

        :returns: the list containing the ECs
        :rtype: list[str]
        """
        try:
            # self.get_trust_anchor_configuration()
            self.get_subject_configuration()
            self.discovery()
        except Exception as e:
            self.is_valid = False
            logger.error(f"{e}")
            raise e

    @property
    def exp_datetime(self) -> datetime.datetime:
        """The exp filed converted in datetime format"""
        if self.exp:  # pragma: no cover
            return datetime_from_timestamp(self.exp)
