from typing import Annotated, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator

_SUPPORTED_KTY = Literal["EC", "RSA"]

_SUPPORTED_ALGS = Literal[
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "RS256",
    "RS384",
    "RS512",
]

_SUPPORTED_ALG_BY_KTY = {
    "RSA": ("PS256", "PS384", "PS512", "RS256", "RS384", "RS512"),
    "EC": ("ES256", "ES384", "ES512")
}

# TODO: supported alg by kty and use

_SUPPORTED_CRVS = Literal[
    "P-256",
    "P-384",
    "P-521",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1"
]


class JwkBaseModel(BaseModel):
    kid: Optional[str]
    use: Optional[Literal["sig", "enc"]] = None


class ECJwkSchema(JwkBaseModel):
    kty: Literal["EC"]
    crv: _SUPPORTED_CRVS
    x: str
    y: str


class RSAJwkSchema(JwkBaseModel):
    kty: Literal["RSA"]
    n: str
    e: str


class JwkSchema(BaseModel):
    kid: str  # Base64url-encoded thumbprint string
    kty: _SUPPORTED_KTY
    alg: Annotated[Union[_SUPPORTED_ALGS, None], Field(validate_default=True)] = None
    use: Annotated[Union[Literal["sig", "enc"], None], Field(validate_default=True)] = None
    n: Annotated[Union[str, None], Field(validate_default=True)] = None  # Base64urlUInt-encoded
    e: Annotated[Union[str, None], Field(validate_default=True)] = None  # Base64urlUInt-encoded
    x: Annotated[Union[str, None], Field(validate_default=True)] = None  # Base64urlUInt-encoded
    y: Annotated[Union[str, None], Field(validate_default=True)] = None  # Base64urlUInt-encoded
    crv: Annotated[Union[_SUPPORTED_CRVS, None], Field(validate_default=True)] = None

    def _must_specific_kty_only(v, exp_kty: _SUPPORTED_ALGS, v_name: str, values: dict):
        """validate a jwk parameter by that it is (1) defined and (2) mandatory
        only for one specific kty by checking that it is indeed defined by when
        kty matches.
        """
        err_msg = f"{v_name} must be present only for kty = {exp_kty}"
        obt_kty: Union[_SUPPORTED_KTY, None] = values.get("kty", None)
        if obt_kty is None:
            if v is not None:
                raise ValueError("unexpected validation state: missing kty")
            return
        if exp_kty == obt_kty:
            if v is None:
                raise ValueError(err_msg)
            return
        # in this validation v should NOT be defined if obt_kty != exp_kty
        if v is not None:
            raise ValueError(err_msg)
        return

    @field_validator("alg")
    def validate_alg(cls, v, values):
        if v is None:
            return
        kty = values.data.get("kty")
        if v not in _SUPPORTED_ALG_BY_KTY[kty]:
            raise ValueError(f"alg value {v} is not compatible or not supported with kty {kty}")
        return

    @field_validator("n")
    def validate_n(cls, v, values):
        cls._must_specific_kty_only(v, "RSA", "n", values.data)

    @field_validator("e")
    def valisate_e(cls, v, values):
        cls._must_specific_kty_only(v, "RSA", "e", values.data)

    @field_validator("x")
    def validate_x(cls, v, values):
        cls._must_specific_kty_only(v, "EC", "x", values.data)

    @field_validator("y")
    def validate_y(cls, v, values):
        cls._must_specific_kty_only(v, "EC", "y", values.data)

    @field_validator("crv")
    def validate_crv(cls, v, values):
        cls._must_specific_kty_only(v, "EC", "crv", values.data)


_JwkSchema_T = Annotated[Union[ECJwkSchema, RSAJwkSchema],
                         Field(discriminator="kty")]


class JwksSchema(BaseModel):
    keys: List[_JwkSchema_T]
