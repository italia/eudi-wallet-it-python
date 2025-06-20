import json
from unittest.mock import Mock

from satosa.context import Context
from satosa.response import Redirect
from satosa.state import State

from pyeudiw.satosa.backend.openid4vp import OpenID4VPBackend
from pyeudiw.satosa.interfaces.request_handler import RequestHandlerInterface
from pyeudiw.satosa.interfaces.response_handler import ResponseHandlerInterface
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.tests.settings import BASE_URL, CONFIG, INTERNAL_ATTRIBUTES


class RequestHandler(RequestHandlerInterface):
    def request_endpoint(
        self, context: Context, *args: tuple
    ) -> Redirect | JsonResponse:
        return self._handle_400(
            context, "Request endpoint not implemented.", NotImplementedError()
        )


class ResponseHandler(ResponseHandlerInterface):
    def response_endpoint(self, context: Context, *args) -> JsonResponse:
        return self._handle_400(
            context, "Response endpoint not implemented.", NotImplementedError()
        )


def test_dynamic_backend_creation():
    CONFIG["endpoints"]["request"] = {
        "module": "pyeudiw.tests.satosa.test_dynamic_backed",
        "class": "RequestHandler",
        "path": "/request_test",
    }

    CONFIG["endpoints"]["response"] = {
        "module": "pyeudiw.tests.satosa.test_dynamic_backed",
        "class": "ResponseHandler",
        "path": "/response_test",
    }

    backend = OpenID4VPBackend(Mock(), INTERNAL_ATTRIBUTES, CONFIG, BASE_URL, "name")

    handlers = backend.register_endpoints()
    published_endpoints = [handlers[i][0] for i in range(len(handlers))]
    assert "^name/.well-known/openid-federation$" in published_endpoints
    assert "^name/response_test$" in published_endpoints
    assert "^name/request_test$" in published_endpoints

    context = Context()
    context.state = State()

    response = backend.request_endpoint(context)
    assert response.status == "400"
    assert (
        json.loads(response.message)["error_description"]
        == "Request endpoint not implemented."
    )

    response = backend.response_endpoint(context)
    assert response.status == "400"
    assert (
        json.loads(response.message)["error_description"]
        == "Response endpoint not implemented."
    )
