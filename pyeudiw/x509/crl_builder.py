from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

class CRLBuilder():
    """
    Class to build a Certificate Revocation List (CRL).
    """

    def __init__(self, issuer: str, private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, next_update: int = 30) -> None:
        """
        Initialize the CRLBuilder with the issuer and private key.

        :param issuer: The issuer of the CRL.
        :type issuer: x509.Name
        :param private_key: The private key of the issuer.
        :type private_key: rsa.RSAPrivateKey
        :param next_update: The number of days until the next update, defaults to 30.
        :type next_update: int
        """
        self.issuer = issuer
        self.private_key = private_key
        self.revoked_certificates = []
        self.crl_builder = x509.CertificateRevocationListBuilder()
        self.crl_builder = self.crl_builder.issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer)]))
        self.crl_builder = self.crl_builder.last_update(datetime.now(timezone.utc))
        self.crl_builder = self.crl_builder.next_update(datetime.now(timezone.utc) + timedelta(days=next_update))

    def add_revoked_certificate(self, serial_number: int, revocation_date: datetime):
        """
        Add a revoked certificate to the CRL.

        :param serial_number: The serial number of the revoked certificate.
        :type serial_number: int
        :param revocation_date: The date when the certificate was revoked.
        :type revocation_date: datetime
        """
        self.crl_builder = self.crl_builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
                .serial_number(serial_number)
                .revocation_date(revocation_date)
                .build(default_backend())
        )

    def sign(self) -> x509.CertificateRevocationList:
        """
        Sign the CRL with the issuer's private key.

        :return: The signed CRL.
        :rtype: x509.CertificateRevocationList
        """
        return self.crl_builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
    
    def to_pem(self) -> bytes:
        """
        Convert the CRL to PEM format.

        :return: The CRL in PEM format.
        :rtype: bytes
        """
        return self.sign().public_bytes(Encoding.PEM)
    
    def to_der(self) -> bytes:
        """
        Convert the CRL to DER format.

        :return: The CRL in DER format.
        :rtype: bytes
        """
        return self.sign().public_bytes(Encoding.DER)