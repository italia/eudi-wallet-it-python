from pyeudiw.satosa.dynamic_backend import DynamicBackend
from satosa.context import Context
from satosa.state import State

from pyeudiw.tests.settings import CONFIG

def test_dynamic_backend_creation():
    CONFIG["dynamic_backend"] = {
        "class_name": "TestDynamicBackend",
        "base_class": {
            "module": "pyeudiw.satosa.default.openid4vp_backend",
            "class": "DefaultOpenID4VPBackend"
        },
        "response_handler": {
            "module": "pyeudiw.satosa.default.response_handler",
            "class": "DefaultResponseHandler"
        },
        "request_backend": {
            "module": "pyeudiw.satosa.default.request_handler",
            "class": "DefaultRequestHandler"
        }
    }

    backend = DynamicBackend(None, None, CONFIG, None, None)

    context = Context()
    context.state = State()    

    try:
        backend.request_endpoint(context)
    except NotImplementedError:
        assert False
    except Exception:
        pass

    try:
        backend.get_response_endpoint(context)
    except NotImplementedError:
        assert False
    except Exception:
        pass

    try:
        backend.response_endpoint(context)
    except NotImplementedError:
        assert False
    except Exception:
        pass

    assert backend._extract_all_user_attributes
    assert backend.check_DPOP
    assert backend._request_endpoint_dpop
    assert backend._handle_400