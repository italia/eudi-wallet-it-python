import zlib
from pyeudiw.jwt.utils import base64_urldecode
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.tools.utils import iat_now
from pyeudiw.federation.http_client import http_get_sync


class StatusListTokenHelper:
    def __init__(self, token: str) -> None:
        """
        Initializes the StatusListTokenHelper instance.
        
        :param token: The JWT token to decode.
        :type token: str

        :raises ValueError: If the token is invalid or the token type is not "statuslist+jwt".
        """

        self.header = decode_jwt_header(token)

        if self.header["typ"] != "statuslist+jwt":
            raise ValueError("Invalid token type")
        
        self.payload = decode_jwt_payload(token)
        
        decoded_status_list = self.payload["status_list"]

        self.bits = decoded_status_list["bits"]

        compressed_data = base64_urldecode(decoded_status_list["lst"])
        self.status_list = zlib.decompress(compressed_data)

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