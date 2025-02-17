def adapt_key_to_JWK(key: dict | JWK | cryptojwt.jwk.JWK) -> JWK:
    """Function adapt_key_to_JWK normalize key representation format to
    the internal JWK.
    """
    if isinstance(key, JWK):
        return key
    if isinstance(key, dict):
        return JWK(key)
    if isinstance(key, cryptojwt.jwk.JWK):
        return JWK(key.to_dict())
    raise ValueError(f"not a valid or supported key format: {type(key)}")
