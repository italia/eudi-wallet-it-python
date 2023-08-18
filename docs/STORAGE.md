# Storage

pyeudiw allows us to use multiple storages with replication.

It defines an abstract storage interface ... [doc TBD here]

with the following methods ... [doc TDB here]


## MongoDB

This storage backed is defined in ....

it has the following collections


### Trust Anchors

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


### Trust Attestations

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


### Sessions
