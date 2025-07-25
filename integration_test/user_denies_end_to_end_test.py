# This file contains a flow that simulates an end-to-end flow from the user
# perspective in the case where he denies to share his credentials at the wallet side.
# From a techical point of view, this flow is the Authorization Error Response flow
# descirbed in OpenID4VP.
# Both same device and cross device are tested.
#
# This integration test should be run with the configuraiton file located in
#    testconfig/potential/wp2uc1/userdenies/pyeudiw_backend.yaml

import re
import time
import urllib.parse

import requests
from playwright.sync_api import sync_playwright, Playwright

from pyeudiw.jwt.utils import decode_jwt_payload
from integration_test.initializer.commons import (
    apply_trust_settings,
    create_authorize_error_response_user_denies,
    create_saml_auth_request,
    extract_content_title_login_page,
    extract_request_uri_login_page,
    get_new_browser_page,
    setup_test_db_engine,
    verify_request_object_jwt,
    verify_status_login_page
)
from integration_test.initializer.settings import TIMEOUT_S


def _same_device_extract_request_uri(e: Exception) -> str:
    request_uri: str = re.search(r'request_uri=(.*?)(?:\'|\s|$)', urllib.parse.unquote_plus(e.args[0])).group(1)
    request_uri = request_uri.rstrip()
    return request_uri


def same_device():
    # initialize the user-agent
    http_user_agent = requests.Session()

    auth_req_url = create_saml_auth_request()
    headers_mobile = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B137 Safari/601.1"
    }
    request_uri = ""

    try:
        _ = http_user_agent.get(
            url=auth_req_url,
            verify=False,
            headers=headers_mobile,
            timeout=TIMEOUT_S
        )
    except requests.exceptions.InvalidSchema as e:
        # custom url scheme such as 'haip' or 'eudiw' will raise this exception
        request_uri = _same_device_extract_request_uri(e)
    except requests.exceptions.ConnectionError as e:
        # universal link such as 'https://wallet.example' will raise this exception
        request_uri = _same_device_extract_request_uri(e.args[0])

    signed_request_obj = http_user_agent.get(
        request_uri,
        verify=False,
        timeout=TIMEOUT_S)

    verify_request_object_jwt(signed_request_obj.text, http_user_agent)

    request_object_claims = decode_jwt_payload(signed_request_obj.text)
    response_uri = request_object_claims["response_uri"]

    wallet_response_data = create_authorize_error_response_user_denies(
        request_object_claims["state"]
    )

    authz_error_response = http_user_agent.post(
        response_uri,
        verify=False,
        data=wallet_response_data,
        timeout=TIMEOUT_S
    )

    assert authz_error_response.status_code == 200
    assert authz_error_response.json().get("redirect_uri", None) is not None

    callback_uri = authz_error_response.json().get("redirect_uri", None)
    satosa_authn_error_response = http_user_agent.get(
        callback_uri,
        verify=False,
        timeout=TIMEOUT_S
    )

    assert satosa_authn_error_response.status_code == 401
    assert "Authentication Failure" in satosa_authn_error_response.text

    http_user_agent.close()
    print("TEST CASE SAME DEVICE PASSED")


def cross_device():

    def _run_cross_device(playwright: Playwright):
        # initialize the user-agent(s)
        wallet_user_agent = requests.Session()
        login_page = get_new_browser_page(playwright)

        # Authentication Flow Step 1: init authentication (pre request endpoint)
        auth_req_url = create_saml_auth_request()
        login_page.goto(auth_req_url)

        verify_status_login_page(login_page, 201)

        request_uri = extract_request_uri_login_page(login_page.content())

        # Authentication Flow Step 2: get request object in request endpoint
        sign_request_obj = wallet_user_agent.get(
            request_uri,
            verify=False,
            timeout=TIMEOUT_S)

        verify_request_object_jwt(sign_request_obj.text, wallet_user_agent)

        request_object_claims = decode_jwt_payload(sign_request_obj.text)
        response_uri = request_object_claims["response_uri"]

        verify_status_login_page(login_page, expected_code=202)

        # Authentication Flow Step 3: user denies and wallet provides an authentication error response in the response endpoint
        wallet_response_data = create_authorize_error_response_user_denies(
            request_object_claims["state"]
        )

        authz_error_response = wallet_user_agent.post(
            response_uri,
            verify=False,
            data=wallet_response_data,
            timeout=TIMEOUT_S
        )

        assert authz_error_response.status_code == 200
        assert authz_error_response.json().get("redirect_uri", None) is None

        # Authentication Flow Step 4: user calls a link ("Vai al servizio") with the response code to finish login page interaction

        # wait that js polling catches the updated backend status
        print("\n...waiting that the page updates...\n")
        time.sleep(1.0)
        verify_status_login_page(login_page, 401)

        # check that the page content was updated
        assert "Autenticazione fallita" in extract_content_title_login_page(login_page.content())

        wallet_user_agent.close()
        login_page.close()
        print("TEST CASE CROSS DEVICE PASSED")

    with sync_playwright() as playwright:
        _run_cross_device(playwright)


if __name__ == "__main__":
    # -- SET UP --
    db_engine_inst = setup_test_db_engine()
    db_engine_inst = apply_trust_settings(db_engine_inst)

    # -- TEST --
    same_device()
    cross_device()

    # -- TEAR DOWN --
    # (no teardown scrictly required as of now)
