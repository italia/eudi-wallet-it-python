import json
from pyeudiw.satosa.backend import OpenID4VPBackend
from satosa.context import Context
from satosa.state import State

from pyeudiw.tests.settings import (
    CONFIG,
    BASE_URL,
    INTERNAL_ATTRIBUTES
)

from satosa.response import Redirect
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.satosa.interfaces.request_handler import RequestHandlerInterface
from pyeudiw.satosa.interfaces.response_handler import ResponseHandlerInterface

from unittest.mock import Mock

class RequestHandler(RequestHandlerInterface):
    def request_endpoint(self, context: Context, *args: tuple) -> Redirect | JsonResponse:
        return self._handle_400(context, "Request endpoint not implemented.", NotImplementedError())
    
class ResponseHandler(ResponseHandlerInterface):
    def response_endpoint(self, context: Context, *args) -> JsonResponse:
        return self._handle_400(context, "Response endpoint not implemented.", NotImplementedError())
    

def test_dynamic_backend_creation():
    CONFIG["endpoints"]["request"] = {
        "module": "pyeudiw.tests.satosa.test_dynamic_backed",
        "class": "RequestHandler"
    }

    CONFIG["endpoints"]["response"] = {
        "module": "pyeudiw.tests.satosa.test_dynamic_backed",
        "class": "ResponseHandler"
    }

    backend = OpenID4VPBackend(Mock(), INTERNAL_ATTRIBUTES, CONFIG, BASE_URL, "name")

    context = Context()
    context.state = State()    

    response = backend.request_endpoint(context)
    assert response.status == '400'
    assert json.loads(response.message)['error_description'] == "Request endpoint not implemented."

    response = backend.response_endpoint(context)
    assert response.status == '400'
    assert json.loads(response.message)['error_description'] == "Response endpoint not implemented."