from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from typing import Literal
from cryptography import x509

class ChainBuilder:
    def __init__(self):
        self.chain = []
        self.certificates_attributes = []

    def gen_certificate(
        self,
        cn: str,
        org_name: str,
        country_name: str,
        email_address: str,
        dns: str,
        uri: str,
        ca: bool,
        path_length: int | None,
        serial_number: int | None = None,
        private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
        crl_distr_point: str | None = None,
        not_valid_before: datetime = datetime.now() - timedelta(days=1),
        not_valid_after: datetime = datetime.now() + timedelta(days=365),
        excluded_subtrees: list[x509.DNSName | x509.UniformResourceIdentifier] | None = None,
        permitted_subtrees: list[x509.DNSName | x509.UniformResourceIdentifier] | None = None,
        key_usage: x509.KeyUsage | None = None,
    ) -> None:
        """
        Generate a certificate and add it to the chain.

        :param cn: Common Name
        :type cn: str
        :param org_name: Organization Name
        :type org_name: str
        :param country_name: Country Name
        :type country_name: str
        :param dns: DNS Name
        :type dns: str
        :param private_key: Private key to use for signing the certificate
        :type private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None
        :param ca: Whether the certificate is a CA certificate
        :type ca: bool
        :param path_length: Path length for the CA certificate, None if not a CA
        :type path_length: int | None
        :param serial_number: Serial number of the certificate, random if None
        :type serial_number: int | None
        :param crl_distr_point: CRL Distribution Point URI, None if not set
        :type crl_distr_point: str | None
        :param not_valid_before: Start date of the certificate validity
        :type not_valid_before: datetime
        :param not_valid_after: End date of the certificate validity
        :type not_valid_after: datetime
        :param excluded_subtrees: List of DNS names to exclude from the certificate
        :type excluded_subtrees: list[x509.DNSName | x509.UniformResourceIdentifier]
        :param permitted_subtrees: List of DNS names to permit in the certificate
        :type permitted_subtrees: list[x509.DNSName | x509.UniformResourceIdentifier]

        :return: None
        """
        if private_key is None:
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
            )

        cert = x509.CertificateBuilder()

        x5c_names = [
            x509.NameAttribute(NameOID.COMMON_NAME,
                cn
            ),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                org_name
            ),
            x509.NameAttribute(NameOID.COUNTRY_NAME,
                country_name
            ),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS,
                email_address
            )
        ]

        subject_names = x509.Name(x5c_names)

        if org_name:
            x5c_names.append(
                x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, org_name)
            )
        
        cert = cert.subject_name(subject_names)

        if not self.certificates_attributes:
            issuer_name = subject_names
        else:
            issuer_name = self.certificates_attributes[0]["subject"]

        cert = cert.issuer_name(issuer_name) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number() if not serial_number else serial_number) \
        .not_valid_before(not_valid_before) \
        .not_valid_after(not_valid_after) \
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length),
            critical=True,
        )

        if crl_distr_point:
            cert = cert.add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(crl_distr_point)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False
            )

        if excluded_subtrees or permitted_subtrees:
            cert = cert.add_extension(
                x509.NameConstraints(
                    permitted_subtrees=permitted_subtrees,
                    excluded_subtrees=excluded_subtrees
                ),
                critical=True
            )
        
        if key_usage:
            cert = cert.add_extension(
                key_usage, True
            )

        cert = cert.add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(uri),
                x509.DNSName(dns)
            ]),
            critical=False
        ) \
        .sign(private_key if len(self.certificates_attributes) == 0 else self.certificates_attributes[0]["private_key"], hashes.SHA256())
        
        self.certificates_attributes.insert(0, {
            "cn": cn,
            "org_name": org_name,
            "country_name": country_name,
            "private_key": private_key,
            "email_address": email_address
        })

        self.chain.insert(0, cert)

    def get_chain(self, encoding: Literal["DER"] | Literal["PEM"] = "DER") -> list[bytes] | list[str]:
        """
        Get the certificate chain.

        :return: The certificate chain
        :rtype: list[bytes] | list[str]
        """
        return [
            cert.public_bytes(Encoding.DER if encoding == "DER" else Encoding.PEM) 
            for cert in self.chain
        ]
    
    def get_ca(self, encoding: Literal["DER"] | Literal["PEM"] = "DER") -> bytes | str:
        """
        Get the CA certificate.

        :return: The CA certificate
        :rtype: bytes | str
        """
        return self.chain[-1].public_bytes(Encoding.DER if encoding == "DER" else Encoding.PEM)
