from typing import Union

from pyeudi.exceptions import ValidationError
from satosa.context import Context

from pyeudiw.jwt.utils import decode_jwt_header, decode_jwt_payload
from pyeudiw.oauth2.dpop import DPoPVerifier
from pyeudiw.openid4vp.schemas.wallet_instance_attestation import (
    WalletInstanceAttestationHeader, WalletInstanceAttestationPayload)
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.tools.base_logger import BaseLogger

from pyeudiw.satosa.exceptions import DPOPValidationError


class BackendDPoP(BaseLogger):
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

        :raises DPOPValidationError: if the DPoP validation fails

        :return:
        :rtype: Union[JsonResponse, None]
        """

        if context.http_headers and 'HTTP_AUTHORIZATION' in context.http_headers:
            # The wallet instance uses the endpoint authentication to give its WIA

            # take WIA
            dpop_jws = context.http_headers['HTTP_AUTHORIZATION'].split()[-1]
            _head = decode_jwt_header(dpop_jws)
            wia = decode_jwt_payload(dpop_jws)

            self._log_debug(
                context, message=f"[FOUND WIA] Headers: {_head} and Payload: {wia}")

            try:
                WalletInstanceAttestationHeader(**_head)
            except ValidationError as e:
                self._log_warning(
                    context, message=f"[FOUND WIA] Invalid Headers: {_head}. Validation error: {e}")
            except Exception as e:
                self._log_warning(
                    context, message=f"[FOUND WIA] Invalid Headers: {_head}. Unexpected error: {e}")

            try:
                WalletInstanceAttestationPayload(**wia)
            except ValidationError as e:
                _msg = f"[FOUND WIA] Invalid WIA: {wia}. Validation error: {e}"
                self._log_warning(context, message=_msg)
                #  return self._handle_401(context, _msg, e)
            except Exception as e:
                _msg = f"[FOUND WIA] Invalid WIA: {wia}. Unexpected error: {e}"
                self._log_warning(context, message=_msg)
                #  return self._handle_401(context, _msg, e)

            try:
                self._validate_trust(context, dpop_jws)
            except Exception:
                _msg = f"Trust Chain validation failed for dpop JWS {dpop_jws}"
                raise DPOPValidationError(_msg)

            try:
                dpop = DPoPVerifier(
                    public_jwk=wia['cnf']['jwk'],
                    http_header_authz=context.http_headers['HTTP_AUTHORIZATION'],
                    http_header_dpop=context.http_headers['HTTP_DPOP']
                )
            except ValidationError as e:
                _msg = f"DPoP validation error: {e}"
                raise DPOPValidationError(_msg)
            except Exception as e:
                _msg = f"DPoP verification error: {e}"
                raise DPOPValidationError(_msg)

            try:
                dpop.validate()
            except Exception:
                _msg = "DPoP validation exception"
                raise DPOPValidationError(_msg)

            # TODO: assert and configure the wallet capabilities
            # TODO: assert and configure the wallet Attested Security Context

        else:
            _msg = (
                "The Wallet Instance doesn't provide a valid Wallet Attestation "
                "a default set of capabilities and a low security level are applied."
            )
            self._log_warning(context, message=_msg)
