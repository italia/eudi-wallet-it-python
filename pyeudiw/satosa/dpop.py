import logging
from pprint import pprint

from typing import Union


from pyeudiw.jwt.utils import unpad_jwt_header, unpad_jwt_payload
from pyeudiw.oauth2.dpop import DPoPVerifier
from pyeudiw.openid4vp.schemas.wallet_instance_attestation import WalletInstanceAttestationPayload
from pyeudiw.satosa.response import JsonResponse


logger = logging.getLogger(__name__)


class BackendDPoP:

    def _request_endpoint_dpop(self, context, *args) -> Union[JsonResponse, None]:
        """ This validates, if any, the DPoP http request header """

        if context.http_headers and 'HTTP_AUTHORIZATION' in context.http_headers:
            # The wallet instance uses the endpoint authentication to give its WIA

            # take WIA
            dpop_jws = context.http_headers['HTTP_AUTHORIZATION'].split()[-1]
            _head = unpad_jwt_header(dpop_jws)
            wia = unpad_jwt_payload(dpop_jws)

            self._log(
                context,
                level='debug',
                message=(
                    f"[FOUND WIA] Headers: {_head} and Payload: {wia}"
                )
            )

            try:
                self._validate_trust(context, dpop_jws)
            except Exception as e:
                _msg = f"Trust Chain validation failed for dpop JWS {dpop_jws}"
                return self.handle_error(
                    context=context,
                    message="invalid_client",
                    troubleshoot=_msg,
                    err_code="401",
                    err=f"{e}"
                )

            try:
                # Validate the WIA before passing it to the verifier
                WalletInstanceAttestationPayload(**wia)
                dpop = DPoPVerifier(
                    public_jwk=wia['cnf']['jwk'],
                    http_header_authz=context.http_headers['HTTP_AUTHORIZATION'],
                    http_header_dpop=context.http_headers['HTTP_DPOP']
                )
            except Exception as e:
                _msg = f"DPoP verification error: {e}"
                return self.handle_error(
                    context=context,
                    message="invalid_client",
                    troubleshoot=_msg,
                    err_code="401",
                    err=f"{e}"
                )

            try:
                dpop.validate()
            except Exception as e:
                _msg = "DPoP validation exception"
                return self.handle_error(
                    context=context,
                    message="invalid_client",
                    troubleshoot=_msg,
                    err=f"{e}",
                    err_code="401"
                )

            # TODO: assert and configure the wallet capabilities
            # TODO: assert and configure the wallet Attested Security Context

        else:
            _msg = (
                "The Wallet Instance doesn't provide a valid Wallet Instance Attestation "
                "a default set of capabilities and a low security level are applied."
            )
            self._log(context, level='warning', message=_msg)
