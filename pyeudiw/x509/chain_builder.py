from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from typing import Literal

class ChainBuilder:
    def __init__(self):
        self.chain = []
        self.certificates_attributes = []

    def gen_certificate(
        self,
        cn: str,
        org_name: str,
        country_name: str,
        dns: str,
        date: datetime,
        private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
        crl_distr_point: str | None = None
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
        :param date: Date of the certificate
        :type date: datetime
        :param private_key: Private key to use for signing the certificate
        :type private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None

        :return: None
        """
        if private_key is None:
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
            )

        cert = x509.CertificateBuilder() \
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME,
                            cn
                        ),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                            org_name
                        ),
                        x509.NameAttribute(NameOID.COUNTRY_NAME,
                            country_name
                        ),
                    ]
                )
            )
        

        cert = cert.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME,
                        cn if len(self.certificates_attributes) == 0 else self.certificates_attributes[0]["cn"]
                    ),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                        org_name if len(self.certificates_attributes) == 0 else self.certificates_attributes[0]["org_name"]
                    ),
                    x509.NameAttribute(NameOID.COUNTRY_NAME,
                        country_name if len(self.certificates_attributes) == 0 else self.certificates_attributes[0]["country_name"]
                    ),
                ]
            )
        ) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(date - timedelta(days=1)) \
        .not_valid_after(date + timedelta(days=365)) \
        

        if len(self.certificates_attributes) == 0:
            cert = cert.add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
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

        cert = cert.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns)]),
            critical=False
        ) \
        .sign(private_key if len(self.certificates_attributes) == 0 else self.certificates_attributes[0]["priivate_key"], hashes.SHA256())
        
        self.certificates_attributes.insert(0, {
            "cn": cn,
            "org_name": org_name,
            "country_name": country_name,
            "private_key": private_key
        })

        self.chain.insert(0, cert)

    def get_chain(self, encoding: Literal["DER"] | Literal["PEM"] = "DER") -> list[bytes] | list[str]:
        """
        Get the certificate chain.

        :return: The certificate chain
        :rtype: list[bytes] | list[str]
        """
        return [
            cert.public_bytes(Encoding.DER if encoding == "DER" else "PEM") 
            for cert in self.chain
        ]
    
    def get_ca(self, encoding: Literal["DER"] | Literal["PEM"] = "DER") -> bytes | str:
        """
        Get the CA certificate.

        :return: The CA certificate
        :rtype: bytes | str
        """
        return self.chain[-1].public_bytes(Encoding.DER if encoding == "DER" else "PEM")