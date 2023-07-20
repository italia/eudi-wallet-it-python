from pyeudiw.tools.qr_code import QRCode


def test_qr_code_init():
    data = "test"
    size = 100
    color = "black"
    logo_path = ""
    use_zlib = True

    qr_code = QRCode(data, size, color, logo_path, use_zlib)

    assert qr_code.qr_code_img.size == (size * 33, size * 33)
    assert qr_code.qr_code_img.getpixel((0, 0)) == (255, 255, 255)


