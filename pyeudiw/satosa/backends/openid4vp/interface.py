import satosa.context
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey

from pyeudiw.satosa.backends.openid4vp.schemas.response import AuthorizeResponsePayload


class AuthorizationResponseParser:
    """
    AuthorizationResponseParser is an interface intended to parse direct POST
    http responses.

    An authorization parser is meant to just parse and eventually validate the
    "lower" applicaiton layer of the transmission, that is, it is used to
    extract an authorization response from the HTTP layer.
    It SHOULD NOT be used to validate the actual content of the response, that
    is, it SHOULD NOT try to validate vp_tokens, presentation_submissions, etc.
    This is a delicate task that that is best suited for a different, dedicated
    object, method or interface.
    """

    def parse_and_validate(
        self, context: satosa.context.Context
    ) -> AuthorizeResponsePayload:
        """
        Parse (and optionally validate) a satosa http request, wrapped in its own
        context, in order to extract an auhtorization response.
        The validation step might include verification tasks; for example if the data is
        reepresented as a jwt, the validation should perform a check on the jwt validity.

        The concrete implementation SHOULD NOT be used to validate the actual content
        of the response, that is, it SHOULD NOT try to validate vp_tokens,
        presentation_submissions, etc.
        This is a delicate task that that is best suited for a different, dedicated
        object, method or interface.

        :param context: an http request wrapped in its own satosa context
        :type context: satosa.context.Context

        :raises pyeudiw.satosa.backends.openid4vp.exceptions.AuthRespParsingException: raised \
            when the http response is malformed.
        :raises pyeudiw.satosa.backends.openid4vp.exceptions.AuthRespValidationException: raised \
            when the http response is syntactically correct, but not valid (for \
            example, it might be an expired token).

        :return: the plain openid4vp authorization response; DCQL is not supported yet
        :rtype: AuthorizeResponsePayload
        """
        raise NotImplementedError


class VpTokenParser:
    """VpTokenParser is an interface that specify that an object is able to
    extract verifiable credentials from a VP token.
    """

    def get_credentials(self) -> dict:
        raise NotImplementedError

    def get_issuer_name(self) -> str:
        """
        Get the issuer name from the token payload.

        :raises MissingIssuer: if the issuer name is missing in the token payload

        :return: the issuer name
        :rtype: str
        """
        raise NotImplementedError


class VpTokenVerifier:
    """VpTokenVerifier is an interface that specify that an object is able to
    verify a vp token.
    The interface supposes that the verification process requires a public
    key (os the token issuer)
    """

    def is_expired(self) -> bool:
        raise NotImplementedError

    def is_revoked(self) -> bool:
        """
        :returns: if the credential is revoked
        """
        raise NotImplementedError

    def is_active(self) -> bool:
        return (not self.is_expired()) and (not self.is_revoked())

    def verify_signature(self, public_key: ECKey | RSAKey | dict) -> None:
        """
        Verifies the signature of the jwt.

        :param public_key: the public key to verify the signature
        :type public_key: ECKey | RSAKey | dict

        :raises JWSVerificationError: if the signature is invalid
        """
        raise NotImplementedError

    def verify_challenge(self) -> None:
        """
        Verifies the challenge of the jwt.

        :raises UnsupportedSdAlg: if verification fails due to an unkown _sd_alg
        :raises InvalidKeyBinding: if the verification fails for a known reason
        :raises ValueError: if the iat claim is missing or invalid
        :raises JWSVerificationError: if the verification of a JWS fails
        """
        raise NotImplementedError

    # TODO: VP proof of possession verification method should be implemented
