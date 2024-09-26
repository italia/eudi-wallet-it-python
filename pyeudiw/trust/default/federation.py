from jwcrypto.jwk import JWK

from pyeudiw.federation.policy import TrustChainPolicy
from pyeudiw.jwt.utils import decode_jwt_payload
from pyeudiw.trust.interface import IssuerTrustModel


class FederationTrustModel(IssuerTrustModel):
    _ISSUER_METADATA_TYPE = "openid_credential_issuer"

    def __init__(self):
        # TODO; qui c'è dentro tutta la ciccia: trust chain verification, root of trust, etc
        self.metadata_policy_resolver = TrustChainPolicy()
        pass

    def _verify_trust_chain(self, trust_chain: list[str]):
        # TODO: qui c'è tutta la ciccia, ma si può fare copia incolla da terze parti (specialmente di pyeudiw.trust.__init__)
        raise NotImplementedError

    def get_verified_key(self, issuer: str, token_header: dict) -> JWK:
        # (1) verifica trust chain
        kid: str = token_header.get("kid", None)
        if not kid:
            raise ValueError("missing claim [kid] in token header")
        trust_chain: list[str] = token_header.get("trust_chain", None)
        if not trust_chain:
            raise ValueError("missing trust chain in federation token")
        if not isinstance(trust_chain, list):
            raise ValueError*("invalid format of header claim [trust_claim]")
        self._verify_trust_chain(trust_chain)  # TODO: check whick exceptions this might raise

        # (2) metadata parsing ed estrazione Jwk set
        # TODO: wrap in something that implements VciJwksSource
        # apply policy of traust anchor only?
        issuer_entity_configuration = trust_chain[0]
        anchor_entity_configuration = trust_chain[-1]
        issuer_payload: dict = decode_jwt_payload(issuer_entity_configuration)
        anchor_payload = decode_jwt_payload(anchor_entity_configuration)
        trust_anchor_policy = anchor_payload.get("metadata_policy", {})
        final_issuer_metadata = self.metadata_policy_resolver.apply_policy(issuer_payload, trust_anchor_policy)
        metadata: dict = final_issuer_metadata.get("metadata", None)
        if not metadata:
            raise ValueError("missing or invalid claim [metadata] in entity configuration")
        issuer_metadata: dict = metadata.get(FederationTrustModel._ISSUER_METADATA_TYPE, None)
        if not issuer_metadata:
            raise ValueError(f"missing or invalid claim [metadata.{FederationTrustModel._ISSUER_METADATA_TYPE}] in entity configuration")
        issuer_keys: list[dict] = issuer_metadata.get("jwks", {}).get("keys", [])
        if not issuer_keys:
            raise ValueError(f"missing or invalid claim [metadata.{FederationTrustModel._ISSUER_METADATA_TYPE}.jwks.keys] in entity configuration")
        # check issuer = entity_id
        if issuer != (obt_iss := final_issuer_metadata.get("iss", "")):
            raise ValueError(f"invalid issuer metadata: expected '{issuer}', obtained '{obt_iss}'")

        # (3) dato il set completo, fa il match per kid tra l'header e il jwk set
        found_jwks: list[dict] = []
        for key in issuer_keys:
            obt_kid: str = key.get("kid", "")
            if kid == obt_kid:
                found_jwks.append(key)
        if len(found_jwks) != 1:
            raise ValueError(f"unable to uniquely identify a key with kid {kid} in appropriate section of issuer entity configuration")
        try:
            return JWK(**found_jwks[0])
        except Exception as e:
            raise ValueError(f"unable to parse issuer jwk: {e}")
