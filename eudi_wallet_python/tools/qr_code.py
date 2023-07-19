import zlib
import qrcode
from PIL import Image

class QRCode():
    def __init__(self, data: str, base_size: dict = {"w": 100, "h": 100}, color: str = '#2B4375', logo_path: str = None, use_zlib: bool = True) -> None:
        compressed_request_data = None
        
        if use_zlib:
            compressed_request_data = zlib.compress(data.encode(), 9)

        qr_code = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_H
        )

        qr_code.add_data(compressed_request_data or data)
        qr_code.make()

        self.qr_code_img = qr_code.make_image(
            fill_color=color,
            back_color="white"
        ).convert('RGB')

        #Add logo if present
        if logo_path:
            logo = Image.open(logo_path)
            wpercent = (base_size["w"]/float(logo.size[0]))
            hsize = int((float(logo.size[1])*float(wpercent)))
            logo = logo.resize((base_size["w"], hsize), Image.ANTIALIAS)
            
            pos = ((self.qr_code_img.size[0] - logo.size[0]) // 2, (self.qr_code_img.size[1] - logo.size[1]) // 2)
            
            self.qr_code_img.paste(logo, pos)
            
    def save(self, path):
        self.qr_code_img.save(path)