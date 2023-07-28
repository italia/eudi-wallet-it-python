import json

from satosa.response import Response


class JsonResponse(Response):
    _content_type = "application/json"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if isinstance(self.message, list):
            self.message = self.message[0]

        if type(self.message) in (list, dict):
            self.message = json.dumps(self.message)
