from datetime import datetime
from cryptography import x509
from cryptography.x509 import CertificateRevocationList
from cryptography.hazmat.backends import default_backend
from pyeudiw.federation.http_client import http_get_sync
from pyeudiw.x509.exceptions import CRLHTTPError, CRLParseError, CRLReadError
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

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

    def is_revoked(self, serial_number: str | int) -> bool:
        """
        Check if a certificate with the given serial number is revoked.

        :param serial_number: The serial number of the certificate to check. Can be in hex format (string) or integer.
        :type serial_number: str | int

        :return: True if the certificate is revoked, False otherwise.
        :rtype: bool
        """
        try:
            if isinstance(serial_number, str):
                serial_number = int(serial_number, 16)
        except ValueError:
            raise CRLReadError(f"Invalid serial number format: {serial_number}")

        try:
            return self.revocation_list.get_revoked_certificate_by_serial_number(serial_number) is not None
        except Exception as e:
            raise CRLReadError(f"Failed to check revocation status: {e}")
        
    def get_revocation_date(self, serial_number: str | int) -> datetime | None:
        """
        Get the revocation date of a certificate with the given serial number.

        :param serial_number: The serial number of the certificate to check. Can be in hex format (string) or integer.
        :type serial_number: str | int

        :return: The revocation date if revoked, None otherwise.
        :rtype: str | None
        """
        try:
            if isinstance(serial_number, str):
                serial_number = int(serial_number, 16)
        except ValueError:
            raise CRLReadError(f"Invalid serial number format: {serial_number}")

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
        if response[0].status_code != 200:
            raise CRLHTTPError(f"Failed to fetch CRL from {crl_url}: {response.status_code}")        

        return CRLHelper.from_crl(response[0].text.encode("utf-8"))
            
    @staticmethod
    def from_certificate(cert: str | bytes) -> list["CRLHelper"]:
        """
        Load CRL distribution points from a given certificate.
        This method extracts the CRL distribution points from the certificate and loads them into CRLHelper instances.

        :param cert: The certificate in PEM or DER format.
        :type cert: str | bytes

        :raises CRLReadError: If the certificate does not contain CRL distribution points or if loading fails.

        :return: A list of CRLHelper instances containing the loaded CRLs.
        :rtype: list[CRLHelper]
        """
        if isinstance(cert, str) and cert.startswith("-----BEGIN CERTIFICATE-----"):
            parsed_cert: x509.Certificate = load_pem_x509_certificate(cert.encode(), default_backend())
        elif isinstance(cert, bytes) and cert.startswith(b"-----BEGIN CERTIFICATE-----"):
            parsed_cert: x509.Certificate = load_pem_x509_certificate(cert, default_backend())
        else:
            parsed_cert: x509.Certificate = load_der_x509_certificate(
                cert.encode() if isinstance(cert, str) else cert, 
                default_backend()
            )

        try:
            crl_distribution_points = parsed_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        except x509.ExtensionNotFound:
            raise CRLReadError("No CRL distribution points found in the certificate.")

        crl_helpers = []

        for crl_url in crl_distribution_points.value:
            try:
                crl_helper = CRLHelper.from_url(crl_url.full_name[0].value)
                crl_helpers.append(crl_helper)
            except (CRLHTTPError, CRLParseError, CRLReadError) as e:
                raise CRLReadError(f"Failed to load CRL from certificate: {e}")
            
        return crl_helpers
    
    @staticmethod
    def from_crl(crl: str | bytes) -> "CRLHelper":
        """
        Load a CRL from a given PEM or DER formatted string or bytes.

        :param crl: The CRL in PEM or DER format.
        :type crl: str | bytes

        :raises CRLParseError: If the CRL file is not in the expected format.

        :return: An instance of CRLHelper containing the loaded CRL.
        :rtype: CRLHelper
        """
        try:
            return CRLHelper(
                x509.load_pem_x509_crl(
                    crl, 
                    default_backend()
                )
            )
        except Exception as e:
            raise CRLParseError(f"Failed to parse CRL: {e}")