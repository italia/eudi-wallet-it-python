class RSAJWK(JWK):
    def __init__(self, key: dict | None = None, hash_func: str = "SHA-256") -> None:
        super().__init__(key, "RSA", hash_func, None)


class ECJWK(JWK):
    def __init__(
        self, key: dict | None = None, hash_func: str = "SHA-256", ec_crv: str = "P-256"
    ) -> None:
        super().__init__(key, "EC", hash_func, ec_crv)


def jwk_form_dict(key: dict, hash_func: str = "SHA-256") -> RSAJWK | ECJWK:
    """
    Returns a JWK instance from a dict.

    :param key: a dict that represents the key.
    :type key: dict

    :returns: a JWK instance.
    :rtype: JWK
    """
    _kty = key.get("kty", None)

    if _kty is None or _kty not in ["EC", "RSA"]:
        raise InvalidJwk("Invalid JWK")
    elif _kty == "RSA":
        return RSAJWK(key, hash_func)
    else:
        ec_crv = key.get("crv", "P-256")
        return ECJWK(key, hash_func, ec_crv)