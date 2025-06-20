import base64
from copy import deepcopy
from typing import Any

import cbor2
import yaml
from jinja2 import Template

from pyeudiw.jwt.utils import base64_urldecode


def from_jwk_to_mso_mdoc_private_key(jwk_key: dict) -> dict:
    """
    Converts a JWK (JSON Web Key) EC private key to a format compatible with MSO/mDoc structures.

    This function transforms a JWK-style elliptic curve private key into a dictionary
    suitable for Mobile Security Object (MSO) or mdoc (mobile document) signing usage.
    It handles key type mapping, curve renaming, and base64url decoding of the private key value.
    """
    match jwk_key["kty"]:
        case "EC":
            kty_mso_mdoc = "EC2"
        case _:
            kty_mso_mdoc =jwk_key["kty"]

    mso_mdoc_private_key ={
        'KTY': kty_mso_mdoc,
        'CURVE': jwk_key["crv"].replace("-", "_"),
        'ALG': jwk_key["alg"],
        'D': base64_urldecode(jwk_key["d"]),
    }
    if jwk_key["kid"]:
        mso_mdoc_private_key["KID"] = jwk_key["kid"].encode("utf-8")
    return mso_mdoc_private_key

def render_mso_mdoc_template(template_str: str, data: dict, transform_config: dict = None) -> dict:
    """
    Render an mso_mdoc YAML template using the provided data.
    Handles base64 for images and CBOR tag 1004 for dates.

    :param template_str: The YAML template as a string (with Jinja2 placeholders).
    :param data: A dictionary of values to populate the template.
    :return: A Python dictionary with the rendered and properly typed content.
    """
    # Add portrait_b64 if portrait is present and is raw bytes
    if transform_config:
        data = _apply_transforms(data, transform_config)

    # Render YAML with Jinja2
    rendered = Template(template_str).render(**data)

    yaml.SafeLoader.add_constructor("!cbor_date", _cbor_date_constructor)

    # Parse YAML into Python dictionary
    return yaml.safe_load(rendered)

def _apply_transforms(data: dict, transform_config: dict) -> dict:
    data = deepcopy(data)

    for field, rules in transform_config.items():
        value: Any = data.get(field)
        if value is None:
            continue

        if rules.get("if_type") == "bytes" and not isinstance(value, bytes):
            continue

        transform_type = rules.get("transform")
        output_field = rules.get("output", field)

        if transform_type == "base64":
            data[output_field] = base64.b64encode(value).decode("utf-8")

    return data

def _cbor_date_constructor(loader, node):
    """ Custom constructor for !cbor_date tag """
    value = loader.construct_scalar(node)
    return cbor2.CBORTag(1004, cbor2.dumps(value))