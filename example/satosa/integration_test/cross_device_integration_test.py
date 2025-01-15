import time
import requests
import urllib.parse

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, Playwright, Page

from pyeudiw.jwt.utils import decode_jwt_payload

from commons import (
    ISSUER_CONF,
    setup_test_db_engine,
    apply_trust_settings,
    create_saml_auth_request,
    create_authorize_response,
    create_holder_test_data,
    create_issuer_test_data,
    extract_saml_attributes,
    verify_request_object_jwt
)
from settings import TIMEOUT_S

# put a trust attestation related itself into the storage
# this is then used as trust_chain header parameter in the signed request object
db_engine_inst = setup_test_db_engine()
db_engine_inst = apply_trust_settings(db_engine_inst)

STATUS_ENDPOINT_URI_JS = "statusEndpoint()+'?id='+sessionIdentifier()"  # javascript functions that yield the status URI; defined in qrcode.html


def _verify_status(login_page: Page, expected_code: int):
    current_status = login_page.evaluate(
        f"fetch({STATUS_ENDPOINT_URI_JS}).then(resp => resp.status)"
    )
    assert expected_code == current_status


def _extract_request_uri(page_content: str) -> str:
    bs = BeautifulSoup(page_content, features="html.parser")
    # Request URI is extracted by parsing the QR code in the response page
    qrcode_element = list(bs.find(id="content-qrcode-payload").children)[1]
    qrcode_text = qrcode_element.get("contents")
    request_uri = urllib.parse.parse_qs(qrcode_text)["request_uri"][0]
    return request_uri


def _get_browser_page(playwright: Playwright) -> Page:
    """
    Returns a browser page that live in a browser instance that is fresh and
    does not share cookies and cache with other browser instances
    """
    webkit = playwright.webkit
    rp_browser = webkit.launch(timeout=0)
    rp_context = rp_browser.new_context(
        ignore_https_errors=True,  # required as otherwise self-signed certificates are not accepted,
        java_script_enabled=True,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36"
    )
    return rp_context.new_page()


def run(playwright: Playwright):
    # initialize the user-agent(s)
    wallet_user_agent = requests.Session()
    login_page = _get_browser_page(playwright)

    # Authentication Flow Step 1: init authentication (pre request endpoint)
    auth_req_url = create_saml_auth_request()
    login_page.goto(auth_req_url)

    _verify_status(login_page, 201)

    request_uri = _extract_request_uri(login_page.content())

    # Authentication Flow Step 2: get request object in request endpoint
    sign_request_obj = wallet_user_agent.get(
        request_uri,
        verify=False,
        timeout=TIMEOUT_S)

    verify_request_object_jwt(sign_request_obj.text, wallet_user_agent)

    request_object_claims = decode_jwt_payload(sign_request_obj.text)
    response_uri = request_object_claims["response_uri"]

    _verify_status(login_page, expected_code=202)

    # Authentication Flow Step 3: wallet provides an authentication response in the response endpoint
    verifiable_credential = create_issuer_test_data()
    verifiable_presentations = create_holder_test_data(
        verifiable_credential,
        request_object_claims["nonce"],
        request_object_claims["client_id"]
    )
    wallet_response_data = create_authorize_response(
        verifiable_presentations,
        request_object_claims["state"],
        response_uri
    )

    authz_response = wallet_user_agent.post(
        response_uri,
        verify=False,
        data={"response": wallet_response_data},
        timeout=TIMEOUT_S
    )

    assert authz_response.status_code == 200
    assert authz_response.json().get("redirect_uri", None) is None

    # Authentication Flow Step 4: user calls a link ("Vai al servizio") with the response code to finish login page interaction

    # wait that js polling catches the updated backend status
    print("\n...waiting that the page updates...\n")
    time.sleep(1.0)
    _verify_status(login_page, 200)

    link_complete_auth = login_page.get_by_role("link")
    link_complete_auth.click(force=True)

    # Test: check response correctness
    satosa_authn_response = login_page.content()
    assert "SAMLResponse" in satosa_authn_response
    print(satosa_authn_response)

    attributes = extract_saml_attributes(satosa_authn_response)
    assert attributes  # expect to have a non-empty list of attributes

    expected = {
        # https://oidref.com/2.5.4.42
        "urn:oid:2.5.4.42": ISSUER_CONF["sd_specification"].split("!sd given_name:")[1].split('"')[1].lower(),
        # https://oidref.com/2.5.4.4
        "urn:oid:2.5.4.4": ISSUER_CONF["sd_specification"].split("!sd family_name:")[1].split('"')[1].lower()
    }

    for exp_att_name, exp_att_value in expected.items():
        result_index = -1
        for i, attribute in enumerate(attributes):
            if attribute["name"] == exp_att_name:
                result_index = i
                break
        assert result_index != -1, f"missing attribute with name=[{exp_att_name}] in result set"
        obt_att_value = attributes[result_index].contents[0].contents[0]
        assert exp_att_value == obt_att_value, f"wrong attribute parsing expected {exp_att_value}, obtained {obt_att_value}"

    print("TEST PASSED")


with sync_playwright() as playwright:
    run(playwright)
