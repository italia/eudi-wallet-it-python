# Storage

`pyeudiw` allows us to use multiple storages with replication.

It defines an abstract storage interface, [`BaseDB`](../pyeudiw/storage/base_db.py), with the methods:
- `_connect`
- `close`.

This class is extended by both [`BaseStorage`](../pyeudiw/storage/base_storage.py) and 
[`BaseCache`](../pyeudiw/storage/base_cache.py) which define the methods needed to query the database.

### Base Storage

The `BaseStorage` class can be extended by implementing the following methods:

| Methods                          |
|----------------------------------|
| `__init__`                       |
| `is_connected`                   |
| `_connect`                       |
| `close`                          |
| `get_by_id`                      |
| `get_by_nonce_state`             |
| `get_by_session_id`              |
| `get_by_state_and_session_id`    |
| `init_session`                   |
| `set_session_retention_ttl`      |
| `has_session_retention_ttl`      |
| `add_dpop_proof_and_attestation` |
| `update_request_object`          |
| `set_finalized`                  |
| `update_response_object`         |
| `_get_trust_attestation`         |
| `get_trust_attestation`          |
| `get_trust_anchor`               |
| `_has_trust_attestation`         |
| `has_trust_attestation`          |
| `has_trust_anchor`               |
| `_update_attestation_metadata`   |
| `_update_anchor_metadata`        |
| `add_trust_attestation`          |
| `add_trust_attestation_metadata` |
| `add_trust_anchor`               |
| `_update_trust_attestation`      |
| `update_trust_attestation`       |
| `update_trust_anchor`            |

Each method and its parameter is documented in the source file.

## MongoDB

The classes [`MongoStorage`](../pyeudiw/storage/mongo_storage.py) and 
 [`MongoCache`](../pyeudiw/storage/mongo_cache.py) provide an implementation of the abstract base classes 
`BaseStorage` and `BaseCache` respectively. 
This classes can be used as references while providing a custom implementation for other databases.

## Trust Anchors

````
    "trust_anchors": {
       "https://ta.example.org": {
          "federation": {
            "entity_configuration": "str(EC), -> EC contains the federation entity public keys,
            "exp": datetime
         },
          "x509": {
            "pem": str(PEM) -> contains public keys,
            "exp": datetime
       }
    }
````


## Trust Attestations

````
    "trust_attestations": {
       "https://wallet_provider.example.org": {
          "federation" : {
            "chain": ARRAY[EC,ES,ES],
            "exp": datetime,
            "update": datetime
          }
          "x509": {
            "x5c": ARRAY[bytestring(DER), bytestring(DER), bytestring(DER)] -> contains public keys,
            "exp": datetime
       }
    }
  }
````

## Sessions

```json
[
  {
    "_id": "`ObjectId`",
    "document_id": "`uuidv4`",
    "creation_date": "`datetime`",
    "session_id": "urn:uuid:`uuidv4`",
    "finalized": "`boolean`",
    "internal_response": "object"
  }
]
```
