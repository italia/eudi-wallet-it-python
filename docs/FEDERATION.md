# federation — OpenID Federation Trust Evaluation

The `pyeudiw.federation` module provides trust evaluation mechanisms according to [OpenID Federation 1.0](https://openid.net/specs/openid-connect-federation-1_0.html).

## Installation

```bash
pip install pyeudiw
```

## Building a Trust Chain

Use `TrustChainBuilder` to walk from a subject (leaf) to a trust anchor and validate the chain. You need a pre-fetched `subject_configuration` (EntityStatement):

```python
from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.federation.statements import EntityStatement, get_entity_configurations

subject = "https://verifier.example.com"
trust_anchor = "https://trust-anchor.example.org"
httpc_params = {"connection": {"timeout": 10}, "session": {}}

# Fetch subject entity configuration
subject_jwts = get_entity_configurations(subject, httpc_params=httpc_params)
subject_configuration = EntityStatement(subject_jwts[0], httpc_params=httpc_params)

builder = TrustChainBuilder(
    subject=subject,
    trust_anchor=trust_anchor,
    httpc_params=httpc_params,
    subject_configuration=subject_configuration,
    max_authority_hints=10,
    required_trust_marks=[{"id": "https://example.org/trustmark"}]
)

# Start discovery and walk the chain
builder.start()

if builder.is_valid:
    metadata = builder.apply_metadata_policy()
    print(metadata)
```

## Validating a Static Trust Chain

When you already have a list of entity statement JWTs (e.g. from cached configuration):

```python
from pyeudiw.federation.trust_chain_validator import StaticTrustChainValidator

# Pre-fetched JWTs: [leaf, intermediate, ..., trust_anchor]
static_chain = [
    "eyJ...",  # Leaf entity statement
    "eyJ...",  # Intermediate
    "eyJ...",  # Trust anchor
]

# Trust anchor public keys for verification
trust_anchor_jwks = [{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}]

validator = StaticTrustChainValidator(
    static_trust_chain=static_chain,
    trust_anchor_jwks=trust_anchor_jwks,
    httpc_params={"connection": {"timeout": 10}}
)

# Optionally refresh from network
validator.update()

if validator.is_valid:
    entity_id = validator.entity_id
    final_metadata = validator.final_metadata
```

## Entity Statements

```python
from pyeudiw.federation.statements import EntityStatement, get_entity_configurations

# Fetch entity configurations from .well-known/openid-federation
jwts = get_entity_configurations(
    "https://example.com",
    httpc_params=httpc_params
)

for jwt in jwts:
    es = EntityStatement(jwt, httpc_params=httpc_params)
    es.validate_by_itself()
```

## Metadata Policy Application

The `TrustChainPolicy` applies metadata policies from the trust anchor to the leaf metadata:

```python
from pyeudiw.federation.policy import TrustChainPolicy

# Typically used internally by TrustChainBuilder and StaticTrustChainValidator

policy = TrustChainPolicy()
# Applied internally by TrustChainBuilder/StaticTrustChainValidator
```

## HTTP Parameters

All federation HTTP calls use `httpc_params`:

```python
httpc_params = {
    "connection": {"timeout": 10},
    "session": {"timeout": 10}
}
```

## Required Trust Marks

You can require specific trust marks for the subject:

```python
required_trust_marks = [
    {"id": "https://trust-mark-issuer.example.org/trustmark-1"}
]

builder = TrustChainBuilder(
    subject=subject,
    trust_anchor=trust_anchor,
    httpc_params=httpc_params,
    subject_configuration=subject_configuration,  # EntityStatement
    required_trust_marks=required_trust_marks
)
```
