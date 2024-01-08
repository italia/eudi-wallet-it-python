from typing import Union
from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop import DPoPVerifier
from pyeudiw.openid4vp.schemas.wallet_instance_attestation import (
    WalletInstanceAttestationPayload,
    WalletInstanceAttestationHeader
)
from pyeudiw.satosa.response import JsonResponse
from satosa.context import Context
from pydantic import ValidationError

from pyeudiw.tools.base_logger import BaseLogger
from .base_http_error_handler import BaseHTTPErrorHandler

class BackendDPoP(BaseHTTPErrorHandler, BaseLogger):
    """
    Backend DPoP class.
    """

    def _request_endpoint_dpop(self, context: Context, *args) -> Union[JsonResponse, None]:
        """
        Validates, if any, the DPoP http request header 
        
        :param context: The current context
        :type context: Context
        :param args: The current request arguments
        :type args: tuple
        
        :return:
        :rtype: Union[JsonResponse, None]
        """

        if context.http_headers and 'HTTP_AUTHORIZATION' in context.http_headers:
            # The wallet instance uses the endpoint authentication to give its WIA

            # take WIA
            dpop_jws = context.http_headers['HTTP_AUTHORIZATION'].split()[-1]
            _head = decode_jwt_header(dpop_jws)
            wia = decode_jwt_payload(dpop_jws)

            self._log_debug(context, message=f"[FOUND WIA] Headers: {_head} and Payload: {wia}")

            try:
                WalletInstanceAttestationHeader(**_head)
            except ValidationError as e:
                self._log_warning(context, message=f"[FOUND WIA] Invalid Headers: {_head}! \nValidation error: {e}")
            except Exception as e:
                self._log_warning(context, message=f"[FOUND WIA] Invalid Headers: {_head}! \nUnexpected error: {e}")

            try:
                WalletInstanceAttestationPayload(**wia)
            except ValidationError as e:
                self._log_warning(context, message=f"[FOUND WIA] Invalid WIA: {wia}! \nValidation error: {e}")
            except Exception as e:
                self._log_warning(context, message=f"[FOUND WIA] Invalid WIA: {wia}! \nUnexpected error: {e}")

            try:
                self._validate_trust(context, dpop_jws)
            except Exception as e:
                _msg = f"Trust Chain validation failed for dpop JWS {dpop_jws}"
                return self._handle_401(context, _msg, e)

            try:
                dpop = DPoPVerifier(
                    public_jwk=wia['cnf']['jwk'],
                    http_header_authz=context.http_headers['HTTP_AUTHORIZATION'],
                    http_header_dpop=context.http_headers['HTTP_DPOP']
                )
            except ValidationError as e:
                _msg = f"DPoP validation error: {e}"
                return self._handle_401(context, _msg, e)
            except Exception as e:
                _msg = f"DPoP verification error: {e}"
                return self._handle_401(context, _msg, e)

            try:
                dpop.validate()
            except Exception as e:
                _msg = "DPoP validation exception"
                return self._handle_401(context, _msg, e)

            # TODO: assert and configure the wallet capabilities
            # TODO: assert and configure the wallet Attested Security Context

        else:
            _msg = (
                "The Wallet Instance doesn't provide a valid Wallet Instance Attestation "
                "a default set of capabilities and a low security level are applied."
            )
            self._log_warning(context, message=_msg)