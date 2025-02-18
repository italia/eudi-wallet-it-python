

class SdJwtKb(SdJwt):
    def __init__(self, token: str):
        if not is_sd_jwt_kb_format(token):
            raise ValueError(
                f"input [token]={token} is not an sd-jwt with key binding with: maybe it is a regular jwt?"
            )
        super().__init__(token)
        if not self.holder_kb:
            raise ValueError("missing key binding jwt")