import urllib.parse
import requests
import urllib
from bs4 import BeautifulSoup
import re

from pyeudiw.jwt.utils import decode_jwt_payload

from commons import (
    ISSUER_CONF,
    apply_trust_settings,
    create_authorize_response,
    create_holder_test_data,
    create_issuer_test_data,
    extract_saml_attributes,
    setup_test_db_engine,
)
from saml2_sp import saml2_request
from settings import TIMEOUT_S

db_engine_inst = setup_test_db_engine()
db_engine_inst = apply_trust_settings(db_engine_inst)

headers_browser = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36"
}


def _verify_status(status_uri: str, expected_code: int):
    status_check = http_user_agent.get(
        status_uri,
        verify=False,
        timeout=TIMEOUT_S
    )
    assert status_check.status_code == expected_code


def _extract_request_uri(bs: BeautifulSoup) -> str:
    # Request URI is extracted by parsing the QR code in the response page
    qrcode_element = list(bs.find(id="content-qrcode-payload").children)[1]
    qrcode_text = qrcode_element.get('contents')
    request_uri = urllib.parse.parse_qs(qrcode_text)['request_uri'][0]
    return request_uri


def _extract_status_uri(bs: BeautifulSoup) -> str:
    # Status uri is extracted by parsing a matching regexp in the <script> portion of the HTML.
    # This funciton is somewhat unstable as it supposes that "qr_code.html" has certain properties
    #  which might not be true.
    qrcode_script_element: str = bs.find_all('script')[-1].string
    qrcode_script_element_formatted = [item.strip() for item in qrcode_script_element.splitlines()]
    qrcode_script_element_formatted = str.join("", qrcode_script_element_formatted)

    status_path = re.search(r'let endpointSatosa = \"(.*?)\"', qrcode_script_element_formatted).group(1)
    resource_id = re.search(r'let data = {\"id\": \"(.*?)\"', qrcode_script_element_formatted).group(1)

    return f"{status_path}?id={resource_id}"


# initialize the user-agent(s)
http_user_agent = requests.Session()
wallet_user_agent = requests.Session()

initiating_saml_request_uri = f"{saml2_request['headers'][0][1]}&idp_hinting=wallet"
request_uri = ""
authn_response = http_user_agent.get(
    url=initiating_saml_request_uri,
    verify=False,
    headers=headers_browser,
    timeout=TIMEOUT_S
)


# Extract request URI and status endpoint by parsing the response page
qrcode_page = BeautifulSoup(authn_response.content.decode(), features="html.parser")
request_uri = _extract_request_uri(qrcode_page)
status_uri = _extract_status_uri(qrcode_page)

# Wallet has not interacted yet: verify that status is 201
_verify_status(status_uri, expected_code=201)

sign_request_obj = wallet_user_agent.get(
    request_uri,
    verify=False,
    timeout=TIMEOUT_S)

request_object_claims = decode_jwt_payload(sign_request_obj.json()['response'])
response_uri = request_object_claims['response_uri']

# Wallet obtained the Request Object; verify that status is 202
_verify_status(status_uri, expected_code=202)

# Provide an authentication response
verifiable_credential = create_issuer_test_data()
verifiable_presentations = create_holder_test_data(
    verifiable_credential,
    request_object_claims['nonce']
)
wallet_response_data = create_authorize_response(
    verifiable_presentations,
    request_object_claims["state"],
    request_object_claims["nonce"],
    response_uri
)

authz_response_feedback = wallet_user_agent.post(
    response_uri,
    verify=False,
    data={'response': wallet_response_data},
    timeout=TIMEOUT_S
)

assert authz_response_feedback.status_code == 200
assert authz_response_feedback.json().get("redirect_uri", None) is None

status_check = http_user_agent.get(
    status_uri,
    verify=False,
    timeout=TIMEOUT_S
)
assert status_check.status_code == 200
assert status_check.json().get("redirect_uri", None) is not None

callback_uri = status_check.json().get("redirect_uri", None)
# TODO: this test does not check that the login page is properly updated with a login button linkint to the redirect uri
satosa_authn_response = http_user_agent.get(
    callback_uri,
    verify=False,
    timeout=TIMEOUT_S
)

assert 'SAMLResponse' in satosa_authn_response.content.decode()
print(satosa_authn_response.content.decode())

attributes = extract_saml_attributes(satosa_authn_response.content.decode())
# expect to have a non-empty list of attributes
assert attributes

expected = {
    # https://oidref.com/2.5.4.42
    "urn:oid:2.5.4.42": ISSUER_CONF['sd_specification'].split('!sd given_name:')[1].split('"')[1],
    # https://oidref.com/2.5.4.4
    "urn:oid:2.5.4.4": ISSUER_CONF['sd_specification'].split('!sd family_name:')[1].split('"')[1]
}

for attribute in attributes:
    name = attribute["name"]
    value = attribute.contents[0].contents[0]
    expected_value = expected.get(name, None)
    if expected_value:
        assert value == expected_value.lower()

print('TEST PASSED')
