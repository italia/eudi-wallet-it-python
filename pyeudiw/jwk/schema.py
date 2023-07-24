from typing import List, Literal, Optional

from pydantic import BaseModel, field_validator


class JwkSchema(BaseModel):
    kid: str  # Base64url-encoded thumbprint string
    kty: Literal["EC", "RSA"]
    # TODO: verify if is optional
    alg: Optional[
        Literal[
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
        ]
    ]
    use: Optional[Literal["sig", "enc"]]
    n: Optional[str]  # Base64urlUInt-encoded
    e: Optional[str]  # Base64urlUInt-encoded

    def check_value_for_rsa(value, name, values):
        if "EC" == values.get("kty") and value:
            raise ValueError(f"{name} must be present only for kty = RSA")

    def check_value_for_ec(value, name, values):
        if "RSA" == values.get("kty") and value:
            raise ValueError(f"{name} must be present only for kty = EC")

    @field_validator("n")
    def validate_n(cls, n_value, values):
        cls.check_value_for_rsa(n_value, "n", values)

    @field_validator("e")
    def validate_e(cls, e_value, values):
        cls.check_value_for_rsa(e_value, "e", values)


class JwkSchemaEC(JwkSchema):
    x: Optional[str]  # Base64url-encoded
    y: Optional[str]  # Base64url-encoded
    crv: Optional[Literal["P-256", "P-384", "P-521"]]

    @field_validator("x")
    def validate_x(cls, x_value, values):
        cls.check_value_for_ec(x_value, "x", values)

    @field_validator("y")
    def validate_y(cls, y_value, values):
        cls.check_value_for_ec(y_value, "y", values)

    @field_validator("crv")
    def validate_crv(cls, crv_value, values):
        cls.check_value_for_ec(crv_value, "crv", values)


class JwksSchemaEC(BaseModel):
    keys: List[JwkSchemaEC]


class JwksSchema(BaseModel):
    keys: List[JwkSchema]
