import base64
import secrets
import string
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CODE_SYM_KEY_LEN = 32  # in bytes (256 bits)


@dataclass
class ResponseCodeSource:
    """ResponseCodeSource is a utility box that wraps a secreet key and
    exposes utility methods that define the relationship between request
    status and response code.

    The class assumes that the response status is a string with UTF-8
    encoding. When this is not true, the resulting chipertext might
    be longer than necessary.

    Constructor arguments:
    :param key: encryption/decryption key, represented as a hex string
    :type key: str
    """

    # repr=False as we do not want to accidentally expose a secret key in a log file
    key: str = field(repr=False)

    def __post_init__(self):
        # Validate input(s)
        _ = decode_key(self.key)

    def create_code(self, state: str) -> str:
        return create_code(state, self.key)

    def recover_state(self, code: str) -> str:
        return recover_state(code, self.key)


def decode_key(key: str) -> bytes:
    if not set(key) <= set(string.hexdigits):
        raise ValueError(
            "key in format different than hex currently not supported")
    key_len = len(key)
    if key_len != 2 * CODE_SYM_KEY_LEN:
        raise ValueError(
            f"invalid key: key should be {CODE_SYM_KEY_LEN} bytes, obtained instead: {key_len//2}")
    return bytes.fromhex(key)


def _base64_encode_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def _base64_decode_no_pad(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def _encrypt_state(msg: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, msg, b'')
    return nonce + ciphertext


def _decrypt_code(encrypted_token: bytes, key: bytes) -> bytes:
    nonce = encrypted_token[:12]
    ciphertext = encrypted_token[12:]
    dec = AESGCM(key).decrypt(nonce, ciphertext, b'')
    return dec


def create_code(state: str, key: str) -> str:
    bkey = decode_key(key)
    msg = bytes(state, encoding='utf-8')
    code = _encrypt_state(msg, bkey)
    return _base64_encode_no_pad(code)


def recover_state(code: str, key: str) -> str:
    bkey = decode_key(key)
    enc = _base64_decode_no_pad(code)
    state = _decrypt_code(enc, bkey)
    return state.decode(encoding='utf-8')
