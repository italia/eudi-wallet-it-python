import logging
from dataclasses import dataclass
from json import dumps
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SDJWTDisclosure:
    """This class represents a disclosure of a claim."""

    issuer: any
    key: Optional[str]  # only for object keys
    value: any

    def __post_init__(self):
        self._hash()

    def _hash(self):
        salt = self.issuer._generate_salt()
        if self.key is None:
            data = [salt, self.value]
        else:
            data = [salt, self.key, self.value]

        self._json = dumps(data).encode("utf-8")

        self._raw_b64 = self.issuer._base64url_encode(self._json)
        self._hash = self.issuer._b64hash(self._raw_b64.encode("ascii"))

    @property
    def hash(self):
        return self._hash

    @property
    def b64(self):
        return self._raw_b64

    @property
    def json(self):
        return self._json.decode("utf-8")
