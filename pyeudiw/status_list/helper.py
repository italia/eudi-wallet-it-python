from typing import Optional
from pyeudiw.tools.utils import iat_now
from pyeudiw.federation.http_client import http_get_sync
from pyeudiw.status_list import decode_jwt_status_list_token, decode_cwt_status_list_token
from pyeudiw.status_list.exceptions import (
    PositionOutOfRangeError,
    InvalidTokenFormatError,
    MissingStatusListUriError,
    StatusListRetrievalError
)

class StatusListTokenHelper:
    def __init__(
            self, 
            header: dict, 
            payload: dict, 
            bits: int, 
            status_list: bytes,
            aggregation_uri: Optional[str] = None
    ) -> None:
        """
        Initializes the StatusListTokenHelper instance.
        
        :param header: The header of the token.
        :type header: dict
        :param payload: The payload of the token.
        :type payload: dict
        :param bits: The number of bits used for the status list.
        :type bits: int
        :param status_list: The status list.
        :type status_list: bytes
        :param aggregation_uri: The aggregation URI.
        :type aggregation_uri: Optional[str]
        """

        self.header = header
        self.payload = payload
        self.bits = bits
        self.status_list = status_list
        self.aggregation_uri = aggregation_uri

    def is_expired(self) -> bool:
        """
        Returns True if the token is expired, False otherwise.

        :returns: True if the token is expired, False otherwise.
        :rtype: bool
        """
        expiration_time = self.payload.get(
            "exp", 
            self.payload.get(4)
        )

        if expiration_time is None:
            return False

        current_time = iat_now()

        return current_time > expiration_time

    def get_status(self, position: int) -> int:
        """
        Returns the status at the given position.

        :param position: The position of the status in the list.
        :type position: int

        :raises IndexError: If the position is out of range.

        :returns: The status at the given position.
        :rtype: int
        """
        total_elemets_number = (len(self.status_list) * 8) // self.bits

        if position < 0:
            raise PositionOutOfRangeError("Position cannot be negative")

        if position >= total_elemets_number:
            raise PositionOutOfRangeError("Position out of range")
        
        jump = self.bits * position
        mask = (1 << self.bits) - 1
        status = (self.status_list[jump // 8] >> (jump % 8)) & mask

        return status
    
    def get_aggregation_uri(self) -> Optional[str]:
        """
        Returns the aggregation URI.

        :returns: The aggregation URI.
        :rtype: Optional[str]
        """
        return self.aggregation_uri
    
    @property
    def ttl(self) -> Optional[int]:
        """
        Returns the time to live (TTL) of the token in seconds.

        :returns: The TTL of the token in seconds.
        :rtype: Optional[int]
        """
        return self.payload.get(
            "ttl", 
            self.payload.get(65534)
        )
    
    @property
    def iss(self) -> Optional[str]:
        """
        Returns the issuer of the token.

        :returns: The issuer of the token.
        :rtype: Optional[str]
        """
        return self.payload.get("iss")
    
    @property
    def sub(self) -> Optional[str]:
        """
        Returns the subject of the token.

        :returns: The subject of the token.
        :rtype: Optional[str]
        """
        return self.payload.get(
            "sub", 
            self.payload.get(2)
        )
    
    @property
    def iat(self) -> Optional[int]:
        """
        Returns the issued at time of the token.

        :returns: The issued at time of the token.
        :rtype: Optional[int]
        """
        return self.payload.get(
            "iat",
            self.payload.get(6)
        )
    
    @staticmethod
    def from_token(token: str | bytes) -> "StatusListTokenHelper":
        """
        Create a StatusListTokenHelper instance from a status list token.
        :param token: The status list token.
        :type token: str | bytes

        :raises InvalidTokenFormatError: If the token is not a valid JWT or CWT.

        :returns: A StatusListTokenHelper instance.
        :rtype: StatusListTokenHelper
        """
        decoders = [decode_jwt_status_list_token, decode_cwt_status_list_token]

        for decoder in decoders:
            status, header, payload, bits, status_list = decoder(token)

            if status:
                return StatusListTokenHelper(header, payload, bits, status_list)

        raise InvalidTokenFormatError(f"Token is not a valid JWT or CWT {token}")
    
    @staticmethod
    def from_status(status: dict, httpc_params: Optional[dict] = None) -> "StatusListTokenHelper":
        """
        Create a StatusListTokenHelper instance from a status dictionary.
        :param status: The status dictionary.
        :type status: dict

        :raises MissingStatusListUriError: If the status list URI is missing.
        :raises StatusListRetrievalError: If there is an error retrieving the status list.
        :raises InvalidTokenFormatError: If the retrieved token is invalid.

        :returns: A StatusListTokenHelper instance.
        :rtype: StatusListTokenHelper
        """

        uri = status.get("status_list", {}).get("uri")

        if uri is None:
            raise MissingStatusListUriError("Status list URI is missing")

        try:
            status_token = http_get_sync(uri, {
                "connection": {"ssl": True},
                "session": {"timeout": 4},
            })
        except Exception as e:
            raise StatusListRetrievalError(f"Failed to retrieve status list token: {e}")

        token = status_token[0].text

        return StatusListTokenHelper.from_token(token)