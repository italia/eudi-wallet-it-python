"""
Wallet Instance Attestation schemas and utilities.

Wallet Instance Attestation (WIA) is used for client authentication in OAuth 2.0
attestation-based flows. This module is independent of OpenID4VP and can be used
by other modules (e.g. OpenID4VCI) that require WIA validation or production.
"""

from pyeudiw.wallet_instance_attestation.models.attestation import (
    VPFormatSchema,
    WalletInstanceAttestationHeader,
    WalletInstanceAttestationPayload,
)
from pyeudiw.wallet_instance_attestation.models.attestation_request import (
    WalletInstanceAttestationRequestHeader,
    WalletInstanceAttestationRequestPayload,
)
from pyeudiw.wallet_instance_attestation.models.cnf import CNFSchema

__all__ = [
    "CNFSchema",
    "VPFormatSchema",
    "WalletInstanceAttestationHeader",
    "WalletInstanceAttestationPayload",
    "WalletInstanceAttestationRequestHeader",
    "WalletInstanceAttestationRequestPayload",
]
