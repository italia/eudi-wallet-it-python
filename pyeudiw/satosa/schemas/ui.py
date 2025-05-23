from pydantic import BaseModel, HttpUrl


class UiConfig(BaseModel):
    static_storage_url: HttpUrl
    template_folder: str
    qrcode_template: str
