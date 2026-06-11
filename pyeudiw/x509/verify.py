import base64
import logging
import re
from datetime import datetime, timezone
from ssl import DER_cert_to_PEM_cert, PEM_cert_to_DER_cert
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey

from pyeudiw.x509.crl_helper import CRLHelper

LOG_ERROR = "x509 verification failed: {}"

logger = logging.getLogger(__name__)

_BASE64_RE = re.compile(
    "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)
# PEM block: -----BEGIN LABEL----- ... -----END LABEL----- (no pyOpenSSL/pem dependency)
_PEM_BLOCK_RE = re.compile(r"-----BEGIN [^-]+-----\n.*?-----END [^-]+-----", re.DOTALL)


def _verify_x509_certificate_chain(pems: list[str], crls: list[CRLHelper]) -> bool:
    """
    Verify the x509 certificate chain using cryptography (no pyOpenSSL).

    :param pems: The x509 certificate chain (PEM strings)
    :type pems: list[str]

    :returns: True if the x509 certificate chain is valid else False
    :rtype: bool
    """
    try:
        certs = [
            load_pem_x509_certificate(pem_str.encode(), default_backend())
            for pem_str in pems
        ]
        if len(certs) < 2:
            return False

        for i in range(len(certs) - 1):
            child, issuer = certs[i], certs[i + 1]
            pubkey = issuer.public_key()
            try:
                if isinstance(pubkey, rsa.RSAPublicKey):
                    pubkey.verify(
                        child.signature,
                        child.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        child.signature_hash_algorithm,
                    )
                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    pubkey.verify(
                        child.signature,
                        child.tbs_certificate_bytes,
                        ec.ECDSA(child.signature_hash_algorithm),
                    )
                else:
                    logging.warning(LOG_ERROR.format("unsupported issuer key type"))
                    return False
            except Exception as e:
                _message = f"chain signature invalid (cert {i} by {i+1}) -> {e}"
                logging.warning(LOG_ERROR.format(_message))
                return False

        for cert in certs:
            serial_number = cert.serial_number
            for crl in crls:
                if crl.is_revoked(serial_number):
                    logging.warning(
                        LOG_ERROR.format(
                            f"certificate with serial number {serial_number} is revoked"
                        )
                    )
                    return False

        return True
    except Exception as e:
        _message = f"cert's chain cannot be validated for error -> {e}"
        logging.warning(LOG_ERROR.format(_message))
        return False


def _check_datetime(exp: datetime | None):
    """
    Check the x509 certificate chain expiration date.

    :param exp: The x509 certificate chain expiration date
    :type exp: datetime.datetime | None

    :returns: True if the x509 certificate chain expiration date is valid else False
    :rtype: bool
    """
    if exp is None:
        return True

    now = datetime.now(timezone.utc)
    exp_utc = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
    if now > exp_utc:
        message = f"expired chain date -> {exp}"
        logging.warning(LOG_ERROR.format(message))
        return False

    return True


def verify_x509_attestation_chain(x5c: list[bytes], crls: list[CRLHelper] = []) -> bool:
    """
    Verify the x509 attestation certificate chain.

    :param x5c: The x509 attestation certificate chain
    :type x5c: list[bytes]

    :returns: True if the x509 attestation certificate chain is valid else False
    :rtype: bool
    """
    try:
        for cert_der in x5c:
            cert = load_der_x509_certificate(to_DER_cert(cert_der), default_backend())
            if not _check_datetime(cert.not_valid_after_utc):
                return False

        pems = [to_PEM_cert(cert) for cert in x5c]

        return _verify_x509_certificate_chain(pems, crls)
    except (ValueError, Exception) as e:
        logging.warning(LOG_ERROR.format(e))
        return False


def DER_cert_to_B64DER_cert(cert: bytes) -> str:
    """
    Encode in Base64 a DER certificate.
    """
    return base64.b64encode(cert).decode()


def PEM_cert_to_B64DER_cert(cert: str) -> str:
    """
    Takes a certificate in ANSII PEM format and returns the base64
    encoding of the corresponding DER certificate.
    """
    return base64.b64encode(PEM_cert_to_DER_cert(cert)).decode()


def B64DER_cert_to_PEM_cert(cert: str) -> str:
    """
    Takes a certificate Base64 encoded DER and returns the
    certificate in ANSII PEM format.
    """
    return DER_cert_to_PEM_cert(base64.b64decode(cert))


def B64DER_cert_to_DER_cert(cert: str) -> bytes:
    """
    Takes a certificate Base64 encoded DER and returns the
    certificate in DER format.
    """
    return base64.b64decode(cert)


def to_DER_cert(cert: str | bytes) -> bytes:
    """
    This function takes in a certificate with unknown representation
    (allegedly, PEM, DER or Base64 encoded DER) and applies some
    heuristics to convert it to a DER certificate.

    This function should be treated as UNSAFE and inefficient. Do NOT
    use it unless you do NOT hany prior way to know the actual representation
    format of a certificate
    """
    cert_s = ""
    if isinstance(cert, bytes):
        if is_der_format(cert):
            return cert
        try:
            cert_s = cert.decode("utf-8")
        except UnicodeDecodeError:
            # Bytes that are not valid DER and not UTF-8 (e.g. malformed DER)
            raise ValueError("unable to recognize input as a certificate")
    else:
        cert_s = cert

    if isinstance(cert, str) and str(cert_s).startswith("-----BEGIN CERTIFICATE-----"):
        return PEM_cert_to_DER_cert(str(cert_s))

    cert_s = re.sub(r"\n\r|\n", "", str(cert_s))
    if _BASE64_RE.fullmatch(cert_s):
        return B64DER_cert_to_DER_cert(cert_s)

    raise ValueError("unable to recognize input as a certificate")


def to_PEM_cert(cert: str | bytes) -> str:
    """
    This function takes in a certificate with unknown representation
    (allegedly, PEM, DER or Base64 encoded DER) and applies some
    heuristics to convert it to a PEM certificate.

    This function should be treated as UNSAFE and inefficient. Do NOT
    use it unless you do NOT hany prior way to know the actual representation
    format of a certificate
    """
    cert_b = b""

    if isinstance(cert, str):
        if is_pem_format(cert):
            return cert
        elif _BASE64_RE.fullmatch(cert):
            cert_b = B64DER_cert_to_DER_cert(cert)
        else:
            cert_b = cert.encode()
    else:
        cert_b = cert

    if isinstance(cert, bytes) and bytes(cert_b).startswith(
        b"-----BEGIN CERTIFICATE-----"
    ):
        return bytes(cert_b).decode()

    try:
        cert_s = bytes(cert_b).decode()
        if _BASE64_RE.fullmatch(cert_s):
            return B64DER_cert_to_PEM_cert(cert_s)
    except UnicodeError:
        return DER_cert_to_PEM_cert(cert_b)

    raise ValueError("unable to recognize input as a certificate")


def pem_to_pems_list(cert: str) -> list[str]:
    """
    Split a string containing one or more PEM blocks (e.g. certificates) into a list of PEM strings.
    Uses stdlib/re only; no pyOpenSSL or pem dependency.

    :param cert: The x509 certificate chain in PEM format (one or more concatenated PEM blocks)
    :type cert: str

    :returns: The x509 certificate chain as a list of PEM strings
    :rtype: list[str]
    """
    return _PEM_BLOCK_RE.findall(cert.strip())


def to_pem_list(der_list: list[bytes] | list[str]) -> list[str]:
    """
    If the input is a list of DER certificates, it will be converted to a list of PEM certificates.
    If the input is a list of PEM certificates, it will be returned as is.

    :param der: The x509 certificate chain in DER format
    :type der: list[bytes]

    :returns: The x509 certificate chain in PEM format
    :rtype: list[str]
    """
    return [to_PEM_cert(cert) for cert in der_list]


def to_der_list(pem_list: list[str] | list[bytes]) -> list[bytes]:
    """
    If the input is a list of PEM certificates, it will be converted to a list of DER certificates.
    If the input is a list of DER certificates, it will be returned as is.

    :param pem_list: The x509 certificate chain in PEM format
    :type pem_list: list[str]

    :returns: The x509 certificate chain in DER format
    :rtype: list[bytes]
    """
    return [to_DER_cert(cert) for cert in pem_list]


def verify_x509_anchor(pem_str: str) -> bool:
    """
    Verify the x509 anchor certificate.

    :param pem_str: The x509 anchor certificate
    :type pem_str: str

    :returns: True if the x509 anchor certificate is valid else False
    :rtype: bool
    """
    cert_data = load_der_x509_certificate(to_DER_cert(pem_str))

    if not _check_datetime(cert_data.not_valid_after_utc):
        logging.error(LOG_ERROR.format("check datetime failed"))
        return False

    pems = pem_to_pems_list(pem_str)

    return _verify_x509_certificate_chain(pems, [])


def get_get_subject_name(der: bytes) -> Optional[str]:
    """
    Get the subject name from the x509 certificate.

    :param der: The x509 certificate
    :type der: bytes

    :returns: The subject name
    :rtype: str
    """
    cert = load_der_x509_certificate(der)

    # get san dns name
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    if san:
        dns = san.value.get_values_for_type(x509.DNSName)
        if dns:
            return dns[0]

        uri = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if uri:
            return uri[0]

    # alternatively erturn the rfc4514 string
    return cert.subject.rfc4514_string()


def get_issuer_from_x5c(x5c: list[bytes] | list[str]) -> Optional[str]:
    """
    Get the issuer from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The issuer
    :rtype: str
    """
    der = to_DER_cert(x5c[0])
    return get_get_subject_name(der)


def get_trust_anchor_from_x5c(x5c: list[bytes] | list[str]) -> Optional[str]:
    """
    Get the issuer from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The issuer
    :rtype: str
    """
    der = to_DER_cert(x5c[-1])
    return get_get_subject_name(der)


def get_expiry_date_from_x5c(x5c: list[bytes] | list[str]) -> datetime:
    """
    Get the expiry date from the x509 certificate chain.

    :param x5c: The x509 certificate chain
    :type x5c: list[bytes]

    :returns: The expiry date
    :rtype: datetime
    """
    der = to_DER_cert(x5c[0])
    cert = load_der_x509_certificate(der)

    return cert.not_valid_after_utc


def get_x509_info(cert: bytes | str, san_dns: bool = True) -> str:
    """
    Get the x509 certificate information.

    :param cert: The x509 certificate
    :type cert: bytes | str
    :param info_type: The information type
    :type info_type: str

    :returns: The certificate information
    :rtype: str
    """

    def get_common_name(cert):
        return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    der = to_DER_cert(cert)
    loaded_cert: x509.Certificate = load_der_x509_certificate(der, default_backend())

    try:
        san = loaded_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        if san_dns:
            return san.value.get_values_for_type(x509.DNSName)[0]

        return get_common_name(loaded_cert)
    except x509.ExtensionNotFound:
        return get_common_name(loaded_cert)


def is_der_format(cert: bytes) -> bool:
    """
    Check if the certificate is in DER format.

    :param cert: The certificate
    :type cert: bytes

    :returns: True if the certificate is in DER format else False
    :rtype: bool
    """
    try:
        pem_str = DER_cert_to_PEM_cert(cert)
        load_pem_x509_certificate(pem_str.encode(), default_backend())
        return True
    except Exception as e:
        logging.error(LOG_ERROR.format(e))
        return False


def is_pem_format(cert: str | bytes) -> bool:
    """
    Check if the certificate is in PEM format.

    :param cert: The certificate
    :type cert: bytes

    :returns: True if the certificate is in PEM format else False
    :rtype: bool
    """
    try:
        data = cert.encode() if isinstance(cert, str) else cert
        load_pem_x509_certificate(data, default_backend())
        return True
    except Exception as e:
        logging.error(LOG_ERROR.format(e))
        return False


def get_public_key_from_x509_chain(x5c: list[bytes]) -> ECKey | RSAKey | dict:
    raise NotImplementedError("TODO")


def get_certificate_type(cert: str | bytes) -> str:
    pem_str = to_PEM_cert(cert)

    loaded_cert = x509.load_pem_x509_certificate(pem_str.encode(), default_backend())
    public_key = loaded_cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RS"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC"
    else:
        return "Unknown"
