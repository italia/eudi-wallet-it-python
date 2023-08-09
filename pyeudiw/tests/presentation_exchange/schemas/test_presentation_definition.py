import pytest
from pydantic import ValidationError

from pyeudiw.presentation_exchange.schemas.presentation_definition import PresentationDefinition, InputDescriptor

PID_SD_JWT = {
    "id": "pid-sd-jwt:unique_id+given_name+family_name",
    "input_descriptors": [
        {
            "id": "sd-jwt",
            "format": {
                "jwt": {
                    "alg": [
                        "EdDSA",
                        "ES256"
                    ]
                },
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {
                            "path": [
                                "$.sd-jwt.type"
                            ],
                            "filter": {
                                "type": "string",
                                "const": "PersonIdentificationData"
                            }
                        },
                        {
                            "path": [
                                "$.sd-jwt.cnf"
                            ],
                            "filter": {
                                "type": "object",
                            }
                        },
                        {
                            "path": [
                                "$.sd-jwt.family_name"
                            ],
                            "intent_to_retain": "true"
                        },
                        {
                            "path": [
                                "$.sd-jwt.given_name"
                            ],
                            "intent_to_retain": "true"
                        },
                        {
                            "path": [
                                "$.sd-jwt.unique_id"
                            ],
                            "intent_to_retain": "true"
                        }
                    ]
                }
            }
        }
    ]
}

MDL_SAMPLE_REQ = {
    "id": "mDL-sample-req",
    "input_descriptors": [
        {
            "id": "mDL",
            "format": {
                "mso_mdoc": {
                    "alg": [
                        "EdDSA",
                        "ES256"
                    ]
                },
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {
                            "path": [
                                "$.mdoc.doctype"
                            ],
                            "filter": {
                                "type": "string",
                                "const": "org.iso.18013.5.1.mDL"
                            }
                        },
                        {
                            "path": [
                                "$.mdoc.namespace"
                            ],
                            "filter": {
                                "type": "string",
                                "const": "org.iso.18013.5.1"
                            }
                        },
                        {
                            "path": [
                                "$.mdoc.family_name"
                            ],
                            "intent_to_retain": "false"
                        },
                        {
                            "path": [
                                "$.mdoc.portrait"
                            ],
                            "intent_to_retain": "false"
                        },
                        {
                            "path": [
                                "$.mdoc.driving_privileges"
                            ],
                            "intent_to_retain": "false"
                        }
                    ]
                }
            }
        }
    ]
}


def test_input_descriptor():
    descriptor = PID_SD_JWT["input_descriptors"][0]
    InputDescriptor(**descriptor)
    descriptor["format"]["jwt"]["alg"] = "ES256"
    with pytest.raises(ValidationError):
        InputDescriptor(**descriptor)
    descriptor["format"]["jwt"]["alg"] = ["ES256"]


def test_presentation_definition():
    PresentationDefinition(**PID_SD_JWT)
    PresentationDefinition(**MDL_SAMPLE_REQ)

    PID_SD_JWT["input_descriptors"][0]["format"]["jwt"]["alg"] = "ES256"
    with pytest.raises(ValidationError):
        PresentationDefinition(**PID_SD_JWT)

    PID_SD_JWT["input_descriptors"][0]["format"]["jwt"]["alg"] = ["ES256"]
    PresentationDefinition(**PID_SD_JWT)

    del PID_SD_JWT["input_descriptors"][0]["format"]["jwt"]["alg"]
    # alg is an emtpy dict, which is not allowed
    with pytest.raises(ValidationError):
        PresentationDefinition(**PID_SD_JWT)

    del PID_SD_JWT["input_descriptors"][0]["format"]["jwt"]
    # since jwt is Optional, this is allowed
    PresentationDefinition(**PID_SD_JWT)

    PID_SD_JWT["input_descriptors"][0]["format"]["jwt"] = {"alg": ["ES256"]}
