import qrcode
import qrcode.image.svg
import zlib

from io import BytesIO


class QRCode:
    def __init__(self, data: str, size: int, color: str, logo_path: str, use_zlib: bool, logo_size_factor: int = 5) -> None:
        compressed_request_data = None
        self.color = color

        if use_zlib:
            compressed_request_data = zlib.compress(data.encode(), 9)

        qr_code = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=size,
        )

        qr_code.add_data(compressed_request_data or data)

        # it must be SVG
        qr_code.make()
        qr_code.image_factory = qrcode.image.svg.SvgImage

        self.qr_code = qr_code

        self.qr_code_img = qr_code.make_image(
            fill_color=color,
            back_color="white"
        )

        # Add logo if present
        if logo_path:
            # TODO - svg doesn't have a size so we need to find another way
            pass
            # logo = Image.open(logo_path)
            # wpercent = (size / float(logo.size[0]))
            # hsize = int((float(logo.size[1]) * float(wpercent)))
            # logo = logo.resize(
            # (size * logo_size_factor, hsize * logo_size_factor), Image.LANCZOS)

            # pos = ((self.qr_code_img.size[0] - logo.size[0]) //
            # 2, (self.qr_code_img.size[1] - logo.size[1]) // 2)

            # self.qr_code_img.paste(logo, pos)

    def save_as_file(self, path) -> str:
        self.qr_code_img.save(path)
        return path

    def as_svg(self) -> BytesIO:
        stream = BytesIO()
        self.qr_code_img.save(stream)
        stream.seek(0)
        return stream

    def for_html(self):
        stream = self.as_svg()
        data = stream.read().decode()
        # data = data.replace(
        # "<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n", ""
        # )
        return data
