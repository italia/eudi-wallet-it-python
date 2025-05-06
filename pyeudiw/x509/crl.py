from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import CertificateRevocationList
from pyeudiw.federation.http_client import http_get_sync
from pyeudiw.x509.exceptions import CRLHTTPError, CRLParseError, CRLReadError

class CRLHelper:
    """
    Helper class to handle CRL (Certificate Revocation List) operations.
    """

    def __init__(self, crl: CertificateRevocationList):
        """
        Initialize the CRLHelper with a CRL object.

        :param crl: The CRL object to be used.
        :type crl: CertificateRevocationList
        """
        self.revocation_list = crl

    def is_revoked(self, serial_number: str) -> bool:
        """
        Check if a certificate with the given serial number is revoked.

        :param serial_number: The serial number of the certificate to check.
        :type serial_number: str

        :return: True if the certificate is revoked, False otherwise.
        :rtype: bool
        """
        try:
            return self.revocation_list.get_revoked_certificate_by_serial_number(serial_number) is not None
        except Exception as e:
            raise CRLReadError(f"Failed to check revocation status: {e}")
        
    def get_revocation_date(self, serial_number: str) -> datetime | None:
        """
        Get the revocation date of a certificate with the given serial number.

        :param serial_number: The serial number of the certificate to check.
        :type serial_number: str

        :return: The revocation date if revoked, None otherwise.
        :rtype: str | None
        """
        try:
            cert = self.revocation_list.get_revoked_certificate_by_serial_number(serial_number)
            return cert.revocation_date if cert else None
        except Exception as e:
            raise CRLReadError(f"Failed to get revocation date: {e}")

    @staticmethod
    def from_url(crl_url: str, httpc_params: dict | None = None) -> "CRLHelper":
        """
        Load a CRL from a given URL.
        This method fetches the CRL file from the specified URL and loads it into a CRL object.
        
        :param crl_url: URL of the CRL file.
        :type crl_url: str
        :param httpc_params: Optional HTTP client parameters.
        :type httpc_params: dict | None

        :raises CRLHTTPError: If the HTTP request fails or the response is not valid.
        :raises CRLParseError: If the CRL file is not in the expected format.

        :return: An instance of CRLHelper containing the loaded CRL.
        :rtype: CRLHelper
        """

        if httpc_params is None:
            httpc_params = {
                "connection": {
                    "timeout": 10,
                    "allow_redirects": True,
                }
            }

        response = http_get_sync([crl_url], httpc_params)
        if response.status_code != 200:
            raise CRLHTTPError(f"Failed to fetch CRL from {crl_url}: {response.status_code}")        

        try:
            return CRLHelper(
                x509.load_pem_x509_crl(
                    response[0].text, 
                    default_backend()
                )
            )
        except Exception as e:
            raise CRLParseError(f"Failed to parse CRL: {e}")
            