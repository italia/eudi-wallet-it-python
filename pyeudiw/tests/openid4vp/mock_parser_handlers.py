from pyeudiw.openid4vp.presentation_submission.base_vp_parser import BaseVPParser

class MockLdpVpHandler(BaseVPParser):
    def __init__(self, *args, config=None, **kwargs):
        self.args = args
        self.config = config
        self.kwargs = kwargs

    def parse(self, data):
        return {"parsed": data}

    def validate(self, data):
        return True


class MockJwtVpJsonHandler(BaseVPParser):
    def __init__(self, *args, config=None, **kwargs):
        self.args = args
        self.config = config
        self.kwargs = kwargs

    def parse(self, data):
        return {"parsed": data}

    def validate(self, data):
        return True