from typing import Optional

from cryptojwt.jwt import utc_time_sans_frac
from pyeudiw.tools.base_logger import BaseLogger

__author__ = "Roland Hedberg"
__license__ = "Apache 2.0"
__version__ = ""


class TrustChain(BaseLogger):
    """
    Class in which to store the parsed result from applying metadata policies on a
    metadata statement.
    """

    def __init__(self,
                 exp: int = 0,
                 verified_chain: Optional[list] = None) -> None:
        """
        Create a TrustChain instance.

        :param exp: Expiration time
        :type exp: int
        :param verified_chain: The verified chain
        :type verified_chain: list
        """
        self.anchor = ""
        self.iss_path = []
        self.err = {}
        self.metadata = {}
        self.exp = exp
        self.verified_chain = verified_chain
        self.combined_policy = {}

    def keys(self) -> list[str]:
        """
        Returns the metadata fields keys

        :return: The metadata fields keys
        :rtype: list
        """
        return self.metadata.keys()

    def items(self) -> list[tuple[str, dict]]:
        """
        Returns the metadata fields items

        :return: The metadata fields items
        :rtype: list[tuple[str, dict]]
        """
        return self.metadata.items()

    def __getitem__(self, item):
        return self.metadata[item]

    def __contains__(self, item):
        return item in self.metadata

    def claims(self):
        """
        The result after flattening the statements
        """
        return self.metadata

    def is_expired(self) -> bool:
        """
        Check if the trust chain is expired.

        :return: True if the trust chain is expired else False
        :rtype: bool
        """
        now = utc_time_sans_frac()
        if self.exp < now:
            self._log_debug(
                "Trust chain",
                f'is_expired: {self.exp} < {now}'
            )
            return True
        else:
            return False

    def export_chain(self) -> list:
        """
        Exports the verified chain in such a way that it can be used as value on the
        trust_chain claim in an authorization or explicit registration request.

        :return: The exported chain in reverse order
        :rtype: list
        """
        _chain = self.verified_chain
        _chain.reverse()
        return _chain

    def set_combined_policy(self, entity_type: str, combined_policy: dict):
        """
        Set the combined policy for the given entity type.

        :param entity_type: The entity type
        :type entity_type: str
        :param combined_policy: The combined policy
        :type combined_policy: dict
        """
        self.combined_policy[entity_type] = combined_policy
