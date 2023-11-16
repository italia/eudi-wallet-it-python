import logging
from typing import List
from typing import Optional

from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from pyeudiw.jwt.utils import unpad_jwt_payload

__author__ = "Roland Hedberg"
__license__ = "Apache 2.0"
__version__ = ""

logger = logging.getLogger(__name__)

class TrustChain(object):
    """
    Class in which to store the parsed result from applying metadata policies on a
    metadata statement.
    """

    def __init__(self,
                 exp: int = 0,
                 verified_chain: Optional[list] = None):
        """
        :param exp: Expiration time
        """
        self.anchor = ""
        self.iss_path = []
        self.err = {}
        self.metadata = {}
        self.exp = exp
        self.verified_chain = verified_chain
        self.combined_policy = {}
    
    def keys(self):
        return self.metadata.keys()

    def items(self):
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

    def is_expired(self):
        now = utc_time_sans_frac()
        if self.exp < now:
            logger.debug(f'is_expired: {self.exp} < {now}')
            return True
        else:
            return False

    def export_chain(self):
        """
        Exports the verified chain in such a way that it can be used as value on the
        trust_chain claim in an authorization or explicit registration request.
        :return:
        """
        _chain = self.verified_chain
        _chain.reverse()
        return _chain
    
    def set_combined_policy(self, entity_type: str, combined_policy: dict):
        self.combined_policy[entity_type] = combined_policy
