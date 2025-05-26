from requests import Response
from cryptography import x509
from unittest.mock import patch
from pyeudiw.x509.crl_helper import CRLHelper
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from pyeudiw.x509.exceptions import CRLReadError, CRLParseError

def generate_certificate(distr_point: bool = True) -> bytes:
    date = datetime.now()

    ca_private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    ca = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME,
                        "CN=ca.example.com, O=Example CA, C=IT"
                    ),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        "Example CA"
                    ),
                    x509.NameAttribute(NameOID.COUNTRY_NAME,
                        "IT"
                    ),
                ]
            )
        )
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME,
                        "CN=ca.example.com, O=Example CA, C=IT"
                    ),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        "Example CA"
                    ),
                    x509.NameAttribute(NameOID.COUNTRY_NAME,
                        "IT"
                    ),
                ]
            )
        )
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(date - timedelta(days=1))
        .not_valid_after(date + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("ca.example.com")]),
            critical=False
        )
    )

    if distr_point:
        ca = ca.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example.com/crl.pem")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False
        )
        
    cert = ca.sign(ca_private_key, hashes.SHA256())

    return cert.public_bytes(Encoding.DER)
    
def test_crl_helper():
    helper = CRLHelper.from_crl(
        b"-----BEGIN X509 CRL-----MIIBcjCB+AIBATAKBggqhkjOPQQDAjBHMRwwGgYDVQQDDBMzU2hhcGUgS01TIFJvb3QgMDAxMRYwFAYDVQQLDA1Ob25wcm9kdWN0aW9uMQ8wDQYDVQQKDAYzU2hhcGUXDTIyMDkyMTE1NTA0OFoXDTI3MDkyMDE1NTA0OFowTjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFOBcNMjIwOTIxMTU0OTI1WjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFORcNMjIwOTIxMTU1MDQ4WqAwMC4wHwYDVR0jBBgwFoAUJlmqlqHSmhcu0m7aSgroirdgdWYwCwYDVR0UBAQCAhABMAoGCCqGSM49BAMCA2kAMGYCMQCDRejYgOYC8zC91vqm4D9X4H3IEjKQKfO3vQFd8iE4Q6ao+dBeIZ342nhosnePVxMCMQCHRXwB3eOkIv7u1gzDvu9bXlsWNG8cgR5coTd0re/zRqN7cXuDlkR+h2mQdb0p/Eg=-----END X509 CRL-----",
        uri="http://crl.example.com/crl.pem"
    )

    assert helper.is_revoked("1B3652D4A9F1494673D4285F4D81302C33894538")
    assert not helper.is_revoked("1B3652D4A9F1494673D4285F4D81302C33894540")

    assert helper.get_revocation_date("1B3652D4A9F1494673D4285F4D81302C33894538") == datetime(2022, 9, 21, 15, 49, 25)
    assert helper.get_revocation_date("1B3652D4A9F1494673D4285F4D81302C33894540") is None


def test_crl_helper_invalid_serial_number():
    helper = CRLHelper.from_crl(
        b"-----BEGIN X509 CRL-----MIIBcjCB+AIBATAKBggqhkjOPQQDAjBHMRwwGgYDVQQDDBMzU2hhcGUgS01TIFJvb3QgMDAxMRYwFAYDVQQLDA1Ob25wcm9kdWN0aW9uMQ8wDQYDVQQKDAYzU2hhcGUXDTIyMDkyMTE1NTA0OFoXDTI3MDkyMDE1NTA0OFowTjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFOBcNMjIwOTIxMTU0OTI1WjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFORcNMjIwOTIxMTU1MDQ4WqAwMC4wHwYDVR0jBBgwFoAUJlmqlqHSmhcu0m7aSgroirdgdWYwCwYDVR0UBAQCAhABMAoGCCqGSM49BAMCA2kAMGYCMQCDRejYgOYC8zC91vqm4D9X4H3IEjKQKfO3vQFd8iE4Q6ao+dBeIZ342nhosnePVxMCMQCHRXwB3eOkIv7u1gzDvu9bXlsWNG8cgR5coTd0re/zRqN7cXuDlkR+h2mQdb0p/Eg=-----END X509 CRL-----",
        uri="http://crl.example.com/crl.pem"
    )

    try:
        helper.is_revoked("invalid_serial_number")
        assert False, "Expected CRLReadError"
    except CRLReadError as e:
        assert str(e) == "Invalid serial number format: invalid_serial_number"

def test_crl_helper_invalid_crl():
    try:
        CRLHelper.from_crl(
            b"-----BEGIN X509 CRL-----invalid_crl-----END X509 CRL-----",
            uri="http://crl.example.com/crl.pem"
        )
        assert False, "Expected CRLParseError"
    except CRLParseError as e:
        assert str(e) == "Failed to parse CRL: Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. InvalidData(InvalidByte(7, 95))"

def test_crl_from_certificate():
    cert = generate_certificate()

    resp = Response()
    resp.status_code = 200
    resp.headers.update({"Content-Type": "application/x509-crl"})
    resp._content = b"-----BEGIN X509 CRL-----MIIBcjCB+AIBATAKBggqhkjOPQQDAjBHMRwwGgYDVQQDDBMzU2hhcGUgS01TIFJvb3QgMDAxMRYwFAYDVQQLDA1Ob25wcm9kdWN0aW9uMQ8wDQYDVQQKDAYzU2hhcGUXDTIyMDkyMTE1NTA0OFoXDTI3MDkyMDE1NTA0OFowTjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFOBcNMjIwOTIxMTU0OTI1WjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFORcNMjIwOTIxMTU1MDQ4WqAwMC4wHwYDVR0jBBgwFoAUJlmqlqHSmhcu0m7aSgroirdgdWYwCwYDVR0UBAQCAhABMAoGCCqGSM49BAMCA2kAMGYCMQCDRejYgOYC8zC91vqm4D9X4H3IEjKQKfO3vQFd8iE4Q6ao+dBeIZ342nhosnePVxMCMQCHRXwB3eOkIv7u1gzDvu9bXlsWNG8cgR5coTd0re/zRqN7cXuDlkR+h2mQdb0p/Eg=-----END X509 CRL-----"

    mock_staus_list_endpoint = patch(
        "pyeudiw.x509.crl_helper.http_get_sync",
        return_value=[
            resp
        ],
    )

    with mock_staus_list_endpoint:
        helpers = CRLHelper.from_certificate(cert)

        assert helpers[0].is_revoked("1B3652D4A9F1494673D4285F4D81302C33894538")
        assert not helpers[0].is_revoked("1B3652D4A9F1494673D4285F4D81302C33894540")

def test_crl_from_certificate_without_distribution_points():
    cert = generate_certificate(distr_point=False)

    try:
        CRLHelper.from_certificate(cert)
        assert False, "Expected CRLReadError"
    except CRLReadError as e:
        assert str(e) == "No CRL distribution points found in the certificate."