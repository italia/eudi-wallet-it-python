"""
Regression tests for the x509 issuing-authority hierarchy checks (CWE-295).

Before the fix the chain verification only checked that each certificate was
signed by the next one, without requiring the signing certificate to actually be
a CA. That let an attacker use any end-entity certificate issued by the trusted
CA to mint arbitrary sub-certificates.
"""

from cryptography import x509

from pyeudiw.x509.chain_builder import ChainBuilder
from pyeudiw.x509.verify import verify_x509_attestation_chain


def _key_usage(key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        key_encipherment=False,
        key_agreement=False,
        content_commitment=False,
        data_encipherment=False,
        encipher_only=False,
        decipher_only=False,
    )


def _cert_params(
    cn: str, ca: bool, path_length: int | None, key_cert_sign: bool = True
) -> dict:
    return dict(
        cn=cn,
        organization_name=cn,
        country_name="IT",
        email_address=f"info@{cn}",
        dns=cn,
        uri=f"https://{cn}",
        ca=ca,
        path_length=path_length,
        key_usage=_key_usage(key_cert_sign),
    )


def _build(chain_specs: list[dict]) -> list[bytes]:
    builder = ChainBuilder()
    for spec in chain_specs:
        builder.gen_certificate(**spec)
    return builder.get_chain("DER")


def test_end_entity_leaf_chain_is_accepted():
    # A perfectly normal chain [leaf(end-entity), intermediate, root].
    chain = _build(
        [
            _cert_params("root.example.com", ca=True, path_length=None),
            _cert_params("intermediate.example.org", ca=True, path_length=0),
            _cert_params(
                "leaf.example.it", ca=False, path_length=None, key_cert_sign=False
            ),
        ]
    )
    assert verify_x509_attestation_chain(chain)


def test_non_ca_issuer_is_rejected():
    # The attack: an end-entity certificate (ca=False) is used to sign a forged
    # certificate. The chain [forged, end-entity, intermediate, root] is
    # internally signature-consistent but must be rejected because the
    # end-entity is not a CA.
    chain = _build(
        [
            _cert_params("root.example.com", ca=True, path_length=None),
            _cert_params("intermediate.example.org", ca=True, path_length=1),
            _cert_params(
                "victim-leaf.example.it",
                ca=False,
                path_length=None,
                key_cert_sign=False,
            ),
            _cert_params(
                "forged.attacker.example",
                ca=False,
                path_length=None,
                key_cert_sign=False,
            ),
        ]
    )
    assert not verify_x509_attestation_chain(chain)


def test_ca_issuer_without_keycertsign_is_rejected():
    # A certificate marked as a CA but whose KeyUsage forbids signing
    # certificates must not be accepted as an issuer.
    chain = _build(
        [
            _cert_params("root.example.com", ca=True, path_length=None),
            _cert_params(
                "intermediate.example.org",
                ca=True,
                path_length=1,
                key_cert_sign=False,
            ),
            _cert_params(
                "leaf.example.it", ca=False, path_length=None, key_cert_sign=False
            ),
        ]
    )
    assert not verify_x509_attestation_chain(chain)


def test_pathlen_constraint_is_enforced():
    # root has pathlen 0, so it may only issue end-entity or leaf CAs directly;
    # a chain that puts another CA below it violates the constraint.
    chain = _build(
        [
            _cert_params("root.example.com", ca=True, path_length=0),
            _cert_params("intermediate.example.org", ca=True, path_length=0),
            _cert_params(
                "leaf.example.it", ca=False, path_length=None, key_cert_sign=False
            ),
        ]
    )
    assert not verify_x509_attestation_chain(chain)
