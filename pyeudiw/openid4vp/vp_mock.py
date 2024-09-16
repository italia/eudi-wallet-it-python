from pyeudiw.openid4vp.verifier import VpVerifier


class MockVpVerifier(VpVerifier):
    def __init__(self, vp_token: str):
        self.vp_token = vp_token

    def verify():
        pass

    def check_revocation_status():
        pass

    def parse_digital_credential() -> dict:
        return {}
