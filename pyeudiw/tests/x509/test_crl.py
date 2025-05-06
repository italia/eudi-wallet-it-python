from datetime import datetime
from pyeudiw.x509.crl import CRLHelper
from pyeudiw.x509.exceptions import CRLReadError, CRLParseError

def test_crl_helper():
    helper = CRLHelper.from_crl(
        b"-----BEGIN X509 CRL-----MIIBcjCB+AIBATAKBggqhkjOPQQDAjBHMRwwGgYDVQQDDBMzU2hhcGUgS01TIFJvb3QgMDAxMRYwFAYDVQQLDA1Ob25wcm9kdWN0aW9uMQ8wDQYDVQQKDAYzU2hhcGUXDTIyMDkyMTE1NTA0OFoXDTI3MDkyMDE1NTA0OFowTjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFOBcNMjIwOTIxMTU0OTI1WjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFORcNMjIwOTIxMTU1MDQ4WqAwMC4wHwYDVR0jBBgwFoAUJlmqlqHSmhcu0m7aSgroirdgdWYwCwYDVR0UBAQCAhABMAoGCCqGSM49BAMCA2kAMGYCMQCDRejYgOYC8zC91vqm4D9X4H3IEjKQKfO3vQFd8iE4Q6ao+dBeIZ342nhosnePVxMCMQCHRXwB3eOkIv7u1gzDvu9bXlsWNG8cgR5coTd0re/zRqN7cXuDlkR+h2mQdb0p/Eg=-----END X509 CRL-----"
    )

    assert helper.is_revoked("1B3652D4A9F1494673D4285F4D81302C33894538")
    assert not helper.is_revoked("1B3652D4A9F1494673D4285F4D81302C33894540")

    assert helper.get_revocation_date("1B3652D4A9F1494673D4285F4D81302C33894538") == datetime(2022, 9, 21, 15, 49, 25)
    assert helper.get_revocation_date("1B3652D4A9F1494673D4285F4D81302C33894540") is None


def test_crl_helper_invalid_serial_number():
    helper = CRLHelper.from_crl(
        b"-----BEGIN X509 CRL-----MIIBcjCB+AIBATAKBggqhkjOPQQDAjBHMRwwGgYDVQQDDBMzU2hhcGUgS01TIFJvb3QgMDAxMRYwFAYDVQQLDA1Ob25wcm9kdWN0aW9uMQ8wDQYDVQQKDAYzU2hhcGUXDTIyMDkyMTE1NTA0OFoXDTI3MDkyMDE1NTA0OFowTjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFOBcNMjIwOTIxMTU0OTI1WjAlAhQbNlLUqfFJRnPUKF9NgTAsM4lFORcNMjIwOTIxMTU1MDQ4WqAwMC4wHwYDVR0jBBgwFoAUJlmqlqHSmhcu0m7aSgroirdgdWYwCwYDVR0UBAQCAhABMAoGCCqGSM49BAMCA2kAMGYCMQCDRejYgOYC8zC91vqm4D9X4H3IEjKQKfO3vQFd8iE4Q6ao+dBeIZ342nhosnePVxMCMQCHRXwB3eOkIv7u1gzDvu9bXlsWNG8cgR5coTd0re/zRqN7cXuDlkR+h2mQdb0p/Eg=-----END X509 CRL-----"
    )

    try:
        helper.is_revoked("invalid_serial_number")
        assert False, "Expected CRLReadError"
    except CRLReadError as e:
        assert str(e) == "Invalid serial number format: invalid_serial_number"

def test_crl_helper_invalid_crl():
    try:
        CRLHelper.from_crl(
            b"-----BEGIN X509 CRL-----invalid_crl-----END X509 CRL-----"
        )
        assert False, "Expected CRLParseError"
    except CRLParseError as e:
        assert str(e) == "Failed to parse CRL: Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. InvalidData(InvalidByte(7, 95))"