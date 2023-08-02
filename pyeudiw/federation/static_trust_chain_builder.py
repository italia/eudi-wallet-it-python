from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import JWS
from dataclasses import dataclass
from pyeudiw.tools.utils import iat_now, exp_from_now


@dataclass
class TrustedAnchorInfo:
    exp_in: int
    issuer: str
    subject: str
    trust_marks: list


@dataclass
class LeafInfo(TrustedAnchorInfo):
    metadata: dict
    authority_hints: list


@dataclass
class IntermediateInfo(TrustedAnchorInfo):
    metadata_policy: dict


def _gen_empty_jwks_field():
    return {"keys": []}


def _gen_ec(node: LeafInfo | IntermediateInfo | TrustedAnchorInfo, keys: list) -> dict:
    ec = {
        # TODO: get all the timestamp dinamically
        'exp': exp_from_now(node.exp_in),
        'iat': iat_now(),
        'iss': node.issuer,
        'sub': node.subject,
        'jwks': _gen_empty_jwks_field(),  # UPDATED LATER IN THE CODE
        'trust_marks': node.trust_marks,
    }

    is_leaf = isinstance(node, LeafInfo)

    if is_leaf:
        ec["metadata"] = node.metadata
        ec["authority_hints"] = node.authority_hints
        ec["metadata"]["openid_relying_party"] = {
            "jwks": _gen_empty_jwks_field()}
    elif isinstance(node, IntermediateInfo):
        ec["metadata_policy"] = node.metadata_policy

    if not isinstance(keys, list):
        keys = [keys]

    for key in keys:
        serialized_key = key.serialize()
        ec["jwks"]['keys'].append(serialized_key)

        if is_leaf:
            ec['metadata']['openid_relying_party']["jwks"]['keys'].append(
                serialized_key)

    return ec


def _sign_ec(ec: dict, jwk: dict) -> str:
    signer = JWS(ec, alg="RS256", typ="application/entity-statement+jwt")
    return signer.sign_compact([jwk])


def gen_static_trustchain(leaf: LeafInfo, intermediate: IntermediateInfo, trusted: TrustedAnchorInfo):
    leaf_jwk = new_rsa_key()
    leaf_ec = _gen_ec(leaf, leaf_jwk)

    intermediate_jwk = new_rsa_key()
    intermediate_ec = _gen_ec(intermediate, leaf_jwk)

    trusted_jwk = new_rsa_key()
    trusted_ec = _gen_ec(trusted, intermediate_jwk)

    return [
        _sign_ec(leaf_ec, leaf_jwk),
        _sign_ec(intermediate_ec, intermediate_jwk),
        _sign_ec(trusted_ec, trusted_jwk),
    ]
