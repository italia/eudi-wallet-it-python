# Storage

`pyeudiw` allows us to use multiple storages with replication.

It defines an abstract storage interface, [`BaseDB`](../pyeudiw/storage/base_db.py), with the methods:
- `_connect`
- `close`.

This class is extended by both [`BaseStorage`](../pyeudiw/storage/base_storage.py) and 
[`BaseCache`](../pyeudiw/storage/base_cache.py) which define the methods needed to query the database.

## MongoDB

The classes [`MongoStorage`](../pyeudiw/storage/mongo_storage.py) and 
 [`MongoCache`](../pyeudiw/storage/mongo_cache.py) provide an implementation of the abstract base classes 
`BaseStorage` and `BaseCache` respectively. 


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
