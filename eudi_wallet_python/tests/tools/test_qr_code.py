import os
import tempfile
from io import BytesIO
from unittest.mock import patch

from PIL import Image

from eudi_wallet_python.tools.qr_code import QRCode


def test_qr_code_init():
    data = "test"
    size = 100
    color = "black"
    logo_path = ""
    use_zlib = True

    qr_code = QRCode(data, size, color, logo_path, use_zlib)

    assert qr_code.qr_code_img.size == (size * 33, size * 33)
    assert qr_code.qr_code_img.getpixel((0, 0)) == (255, 255, 255)


def test_qr_code_init_with_logo():
    data = "test"
    size = 100
    color = "black"

    use_zlib = True

    def create_in_memory_image(path):
        in_memory_file = BytesIO()
        image = Image.new('RGB',
                          size=(10, 10),
                          color=(255, 255, 0))
        image.save(in_memory_file,
                   'png')
        in_memory_file.name = path
        in_memory_file.seek(0)
        return in_memory_file

    with tempfile.NamedTemporaryFile(suffix='.png', delete=True) as temp_file:
        temp_file.write(create_in_memory_image(temp_file.name).read())

        temp_file.file.seek(0)  # change the position to the beginning of the file
        qr_code = QRCode(data, size, color, temp_file.name, use_zlib).qr_code_img

        assert qr_code.getpixel((0, 0)) == (255, 255, 255)
        assert qr_code.getpixel((qr_code.size[0] - 1, qr_code.size[1] - 1)) == (255, 255, 255)
        assert qr_code.getpixel((qr_code.size[0] // 2, qr_code.size[1] // 2)) == (255, 255, 0)
