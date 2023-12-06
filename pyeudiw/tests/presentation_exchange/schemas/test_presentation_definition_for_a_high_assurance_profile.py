import json
from pathlib import Path

from pyeudiw.presentation_exchange.schemas.oid4vc_presentation_definition import \
    PresentationDefinition


def test_presentation_definition():
    p = Path(__file__).with_name('presentation_definition_sd_jwt_vc.json')
    with open(p) as json_file:
        data = json.load(json_file)
        PresentationDefinition(**data)

