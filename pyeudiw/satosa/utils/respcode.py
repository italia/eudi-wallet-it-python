import base64
import hashlib
import hmac


def create_response_code(state: str, key: str) -> str:
    bkey = base64.b64decode(key)
    code = hmac.new(bkey, msg=state.encode(), digestmod=hashlib.sha256)
    b64code = base64.urlsafe_b64encode(code.digest()).decode().strip("=")
    return b64code


def validate_resp_code(obt_b64code: str, state: str, key: str) -> bool:
    bkey = base64.b64decode(key)
    exp_code = hmac.new(bkey, msg=state.encode(), digestmod=hashlib.sha256)
    exp_b64code = base64.urlsafe_b64encode(exp_code.digest()).decode().strip("=")
    # comparison must be evaluated in constant time to avoid timing-based side channel attacks
    return hmac.compare_digest(exp_b64code, obt_b64code)
