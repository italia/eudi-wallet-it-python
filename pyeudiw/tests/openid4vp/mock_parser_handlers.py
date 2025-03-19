from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser

class MockLdpVpHandler(BaseVPParser):
    def __init__(self, *args, config=None, **kwargs):
        self.args = args
        self.config = config
        self.kwargs = kwargs

    def parse(self, data):
        return {"parsed": data}

    def validate(self, data, verifier_id, verifier_nonce):
        return True


class MockJwtVpJsonHandler(BaseVPParser):
    def __init__(self, *args, config=None, **kwargs):
        self.args = args
        self.config = config
        self.kwargs = kwargs

    def parse(self, data):
        return {"parsed": data}

    def validate(self, data, verifier_id, verifier_nonce):
        return True
    
class MockFailingParser(BaseVPParser):
    def __init__(self, *args, config=None, **kwargs):
        self.args = args
        self.config = config
        self.kwargs = kwargs

    def parse(self, data):
        raise ValueError("This parser is meant to fail.")

    def validate(self, data, verifier_id, verifier_nonce):
        return True