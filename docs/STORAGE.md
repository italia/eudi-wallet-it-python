# Storage

`pyeudiw` empowers developers to harness multiple storage solutions with replication capabilities.

It establishes a versatile abstract storage interface, [`BaseDB`](../pyeudiw/storage/base_db.py), 
featuring crucial methods:
- `_connect`: establishes a connection to the storage
- `close`: closes the connection.

This foundational class serves as base for both [`BaseStorage`](../pyeudiw/storage/base_storage.py) and 
[`BaseCache`](../pyeudiw/storage/base_cache.py), 
extending its capabilities to include essential database querying methods.

### Base Storage

The `BaseStorage` class can be extended by implementing the following methods:

-  `__init__`                       
-  `is_connected`                   
-  `_connect`                       
-  `close`                          
-  `get_by_id`                      
-  `get_by_nonce_state`             
-  `get_by_session_id`              
-  `get_by_state_and_session_id`    
-  `init_session`                   
-  `set_session_retention_ttl`      
-  `has_session_retention_ttl`      
-  `add_dpop_proof_and_attestation` 
-  `update_request_object`          
-  `set_finalized`                  
-  `update_response_object`         
-  `_get_trust_attestation`         
-  `get_trust_attestation`          
-  `get_trust_anchor`               
-  `_has_trust_attestation`         
-  `has_trust_attestation`          
-  `has_trust_anchor`               
-  `_update_attestation_metadata`   
-  `_update_anchor_metadata`        
-  `add_trust_attestation`          
-  `add_trust_attestation_metadata` 
-  `add_trust_anchor`               
-  `_update_trust_attestation`      
-  `update_trust_attestation`       
-  `update_trust_anchor`            

Each method and its parameter is documented in the source file.

## BaseCache

The `BaseCache` class implements the following methods:
 
- `try_retrieve`: return a tuple with the retrieved object and a status from cache by param name
- `overwrite`: overrides the object value present in the cache.
- `set`: sets the object value in the cache.

## MongoDB

In the realm of pyeudiw, seamless integration with MongoDB is facilitated through specialized classes, namely 
[`MongoStorage`](../pyeudiw/storage/mongo_storage.py) and [`MongoCache`](../pyeudiw/storage/mongo_cache.py).  

These classes not only offer a robust implementation but also serve as tangible representations of the abstract base 
classes, `BaseStorage` and `BaseCache`.
This classes can be used as references while providing a custom implementation for other databases.
For a complete list of the MongoDB configuration parameters, see [README.SATOSA.md](/README.SATOSA.md#storage)

### Data Examples in MongoDB

#### Trust Anchors

```json
[  
  {
    "_id": ObjectId,
    "entity_id": string,
    "federation": {
      "entity_configuration": str(EC), -> EC contains the federation entity public keys,
      "exp": datetime
    },
    "x509": {
      "pem": str(PEM) -> contains public keys,
      "exp": datetime
    }
  }
]
```

| Name                 | Description                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------ | 
| `_id`                | Unique identifier in MongoDB.                                                                                            |
| `entity_id`          | The string which uniquely identifies the entity.                                                                         |



### Trust Attestations

```json
[
  {
    "_id": ObjectId,
    "entity_id": string,
    "federation" : {
      "chain": ARRAY[EC,ES,ES],
      "exp": datetime,
      "update": datetime,
      "jwks": {
        "keys": ARRAY[object]
      },
    },
    "x509": {
      "x5c": ARRAY[bytestring(DER), bytestring(DER), bytestring(DER)] -> contains public keys,
      "exp": datetime,
      "jwks": {
        "keys": ARRAY[object]
      },
    },
    "direct_trust_sd_jwt_vc": {
      "jwks": {
        "keys": ARRAY[object]
      }
    }
    "metadata": object
  }
]
```

| Name                 | Description                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------ | 
| `_id`                | Unique identifier in MongoDB.                                                                                            |
| `entity_id`          | The string which uniquely identifies the entity.                                                                         |
| `metadata`           | Object containing additional properties.                                                                                 |

#### Sessions

```json
[
  {
    "_id": ObjectId,
    "document_id": uuidv4,
    "creation_date": datetime,
    "state": uuidv4,
    "session_id": "urn:uuid:"uuidv4,
    "remote_flow_typ": string,
    "finalized": boolean,
    "internal_response": object
  }
]
```

| Name                 | Description                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------ | 
| `_id`                | Unique identifier in MongoDB.                                                                                            |
| `document_id`        | A unique identifier shared among each database.                                                                          |
| `creation_date`      | Creation date of the session.                                                                                            |
| `state`              | A unique identifier used to identify a session even among different devices.                                             |
| `session_id`         | Session id. Used to identify cross device flows.                                                                         |
| `remote_flow_typ`    | A string value that discriminates between different authentication flow                                                  |
| `finalized`          | A boolean value which indicates if the session is finilazed or not (user scanned the QR Code or used the redirect link). |
| `internal_response`  | The object containing the personal data, `null` until login.                                                             |
