import zlib
from json import loads
from pyeudiw.jwt.utils import base64_urldecode

class StatusListHelper:
    def __init__(self, status_list: str) -> None:
        decoded_status_list = loads(status_list)
        self.bits = decoded_status_list["bits"]

        compressed_data = base64_urldecode(decoded_status_list["lst"])
        self.status_list = zlib.decompress(compressed_data)

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
