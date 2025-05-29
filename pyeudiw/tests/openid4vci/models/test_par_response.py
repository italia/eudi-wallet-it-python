import json
from satosa.response import Created

from pyeudiw.openid4vci.models.par_response import ParResponse
from pyeudiw.tools.content_type import APPLICATION_JSON, ContentTypeUtils


def test_to_created_response():
    request_uri = "urn:example:par/request/abc123"
    expires_in = 600

    response = ParResponse.to_created_response(request_uri, expires_in)

    assert isinstance(response, Created)
    assert ContentTypeUtils.get_content_type_header(response.headers) == APPLICATION_JSON

    data = json.loads(response.message)
    assert data["request_uri"] == request_uri
    assert data["expires_in"] == expires_in
