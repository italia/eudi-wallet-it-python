import base64
import io

import pyqrcode


class QRCode:
    def __init__(self, data: str, size: int, color: str, **kwargs):
        """
        Create a QR code from the given data
        :param data: The data to be encoded
        :param size: The size of the QR code. Maps to scale in pyqrcode
        :param color: The color of the QR code
        """
        self.data = data
        self.size = size
        self.color = color

        qr = pyqrcode.create(data)
        # Copy the svg data to a string and close the buffer to avoid memory leaks
        buffer = io.BytesIO()
        qr.svg(buffer, scale=size, background="white", module_color=color)
        self.svg = buffer.getvalue().decode("utf-8")
        buffer.close()

    def to_svg(self) -> str:
        """
        Returns the svg data for the QR code as a string
        :return: The svg data for the QR code
        :rtype: str
        """
        return self.svg

    def to_base64(self) -> str:
        """
        Returns the svg data for html
        :return: The svg data for html, base64 encoded
        :rtype: str
        """
        return base64.b64encode(self.svg.encode()).decode('utf-8')

    def to_html(self) -> str:
        """
        Returns the svg data in a html img tag, encoded as base64
        :return: Image tag with svg data for html
        :rtype: str
        """
        b64 = self.to_base64()
        return f'<img src="data:image/svg+xml;base64,{b64}">'
