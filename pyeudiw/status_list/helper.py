from pyeudiw.tools.utils import iat_now
from pyeudiw.federation.http_client import http_get_sync
from pyeudiw.status_list import _decode_jwt_status_list_token, _decode_cwt_status_list_token

class StatusListTokenHelper:
    def __init__(self, header: dict, payload: dict, bits: int, status_list: bytes) -> None:
        """
        Initializes the StatusListTokenHelper instance.
        
        :param header: The JWT header.
        :type header: dict
        :param payload: The JWT payload.
        :type payload: dict
        :param bits: The number of bits used for the status list.
        :type bits: int
        :param status_list: The status list as a byte array.
        :type status_list: bytes
        """

        self.header = header
        self.payload = payload
        self.bits = bits
        self.status_list = status_list

    def is_expired(self) -> bool:
        """
        Returns True if the token is expired, False otherwise.

        :returns: True if the token is expired, False otherwise.
        :rtype: bool
        """
        expiration_time = self.payload["exp"]
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

        if position >= total_elemets_number:
            raise IndexError("Position out of range")

        if position < 0:
            raise IndexError("Position out of range")
        
        jump = self.bits * position
        mask = (1 << self.bits) - 1
        status = (self.status_list[jump // 8] >> (jump % 8)) & mask

        return status
    
    @staticmethod
    def from_token(token: str | bytes) -> "StatusListTokenHelper":
        """
        Create a StatusListTokenHelper instance from a status list token.
        :param token: The status list token.
        :type token: str | bytes

        :raises ValueError: If the token is invalid or the retrieved token is invalid.  

        :returns: A StatusListTokenHelper instance.
        :rtype: StatusListTokenHelper
        """
        decoders = [_decode_jwt_status_list_token, _decode_cwt_status_list_token]

        for decoder in decoders:
            try:
                header, payload, bits, status_list = decoder(token)
                return StatusListTokenHelper(header, payload, bits, status_list)
            except Exception:
                continue

        raise ValueError("Invalid token format")
    
    @staticmethod
    def from_status(status: dict) -> "StatusListTokenHelper":
        """
        Create a StatusListTokenHelper instance from a status dictionary.
        :param status: The status dictionary.
        :type status: dict

        :raises ValueError: If the status dictionary is invalid or the retrieved token is invalid.  

        :returns: A StatusListTokenHelper instance.
        :rtype: StatusListTokenHelper
        """
        try:
            uri = status["status_list"]["uri"]
        except KeyError:
            raise ValueError("Invalid status dictionary")

        status_token = http_get_sync(uri, {
            "connection": {"ssl": True},
            "session": {"timeout": 4},
        })

        token = status_token[0].text

        return StatusListTokenHelper(token)