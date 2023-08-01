# pip install cryptojwt
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import JWS

# Create private keys
leaf_jwk = new_ec_key("P-256")
intermediate_jwk = new_ec_key("P-256")
ta_jwk = new_ec_key("P-256")

# Define Entity Configurations
leaf_ec = {'exp': 1649590602, # TODO: get all the timestamp dinamically
 'iat': 1649417862,
 'iss': 'https://rp.example.org',
 'sub': 'https://rp.example.org',
 'jwks': {}, # UPDATED LATER IN THE CODE
 'metadata': {'openid_relying_party': {'application_type': 'web',
   'client_id': 'https://rp.example.org/',
   'client_registration_types': ['automatic'],
   'jwks': {}, # UPDATED LATER IN THE CODE
   'client_name': 'Name of an example organization',
   'contacts': ['ops@rp.example.it'],
   'grant_types': ['refresh_token', 'authorization_code'],
   'redirect_uris': ['https://rp.example.org/oidc/rp/callback/'],
   'response_types': ['code'],
   'scopes': 'eu.europa.ec.eudiw.pid.1 eu.europa.ec.eudiw.pid.it.1 email',
   'subject_type': 'pairwise'},
  'federation_entity': {'federation_resolve_endpoint': 'https://rp.example.org/resolve/',
   'organization_name': 'Example RP',
   'homepage_uri': 'https://rp.example.it',
   'policy_uri': 'https://rp.example.it/policy',
   'logo_uri': 'https://rp.example.it/static/logo.svg',
   'contacts': ['tech@example.it']}},
 'trust_marks': [{'id': 'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/public/',
   'trust_mark': 'eyJh …'}],
 'authority_hints': ['https://intermediate.eidas.example.org']}


intermediate_ec = {'exp': 1649631824,
 'iat': 1649459024,
 'iss': 'https://intermediate.eidas.example.org',
 'sub': 'https://intermediate.eidas.example.org',
 'jwks': {}, # UPDATED LATER IN THE CODE
 'metadata': {'federation_entity': {'contacts': ['soggetto@intermediate.eidas.example.it'],
   'federation_fetch_endpoint': 'https://intermediate.eidas.example.org/fetch/',
   'federation_resolve_endpoint': 'https://intermediate.eidas.example.org/resolve/',
   'federation_list_endpoint': 'https://intermediate.eidas.example.org/list/',
   'homepage_uri': 'https://soggetto.intermediate.eidas.example.it',
   'name': 'Example Intermediate intermediate.eidas.example'}},
 'trust_marks': [{'id': 'https://registry.gov.org/intermediate/private/full/',
   'trust_mark': 'eyJh …'}],
 'authority_hints': ['https://registry.eidas.trust-anchor.example.eu']}


ta_ec = {'exp': 1649375259,
 'iat': 1649373279,
 'iss': 'https://registry.eidas.trust-anchor.example.eu/',
 'sub': 'https://registry.eidas.trust-anchor.example.eu/',
 'jwks': {}, # UPDATED LATER IN THE CODE
 'metadata': {'federation_entity': {'organization_name': 'example TA',
   'contacts': ['tech@eidas.trust-anchor.example.eu'],
   'homepage_uri': 'https://registry.eidas.trust-anchor.example.eu/',
   'logo_uri': 'https://registry.eidas.trust-anchor.example.eu/static/svg/logo.svg',
   'federation_fetch_endpoint': 'https://registry.eidas.trust-anchor.example.eu/fetch/',
   'federation_resolve_endpoint': 'https://registry.eidas.trust-anchor.example.eu/resolve/',
   'federation_list_endpoint': 'https://registry.eidas.trust-anchor.example.eu/list/',
   'federation_trust_mark_status_endpoint': 'https://registry.eidas.trust-anchor.example.eu/trust_mark_status/'}},
 'trust_marks_issuers': {'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/public/': ['https://registry.spid.eidas.trust-anchor.example.eu/',
   'https://public.intermediary.spid.org/'],
  'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/private/': ['https://registry.spid.eidas.trust-anchor.example.eu/',
   'https://private.other.intermediary.org/']},
 'constraints': {'max_path_length': 1}}

# place example keys
leaf_ec["jwks"]['keys'][0] = leaf_jwk.serialize()
leaf_ec['metadata']['openid_relying_party']["jwks"]['keys'][0] = leaf_jwk.serialize()

intermediate_ec["jwks"]['keys'][0] = intermediate_jwk.serialize()
ta_ec["jwks"]['keys'][0] = ta_jwk.serialize()

# pubblica: dict = privata.serialize()
# privata_dict: dict = privata.to_dict()

# Define Entity Statements
intermediate_es = {
    "exp": 1649623546,
    "iat": 1649450746,
    "iss": "https://intermediate.eidas.example.org",
    "sub": "https://rp.example.org",
    "jwks": {
   	 "keys": [
   		 {
       		 "kty": "RSA",
       		 "n": " …",
       		 "e": "AQAB",
       		 "kid": "2HnoFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMEEs",
        "x5c": ["..."]
   		 }
   	 ]
    },
	"metadata_policy": {
   		 "openid_relying_party": {
       		 "scopes": {
           		 "subset_of": [
                     	"eu.europa.ec.eudiw.pid.1,  eu.europa.ec.eudiw.pid.it.1"
                  	]
       		 },
  	    	"request_authentication_methods_supported": {
  		      "one_of": ["request_object"]
    		 },
  	    	"request_authentication_signing_alg_values_supported": {
  		      "subset_of": ["RS256", "RS512", "ES256", "ES512", "PS256", "PS512"]
          	}
          	}
   	 },
    "trust_marks": [
   	 {
   		 "id": "https://trust-anchor.example.eu/openid_relying_party/public/",
   		 "trust_mark": "eyJhb …"
   	 }
    ]
}

# the leaf publishes the leaf public key
intermediate_es["jwks"]['keys'][0] = leaf_jwk.serialize()


ta_es = {
	"exp": 1649623546,
	"iat": 1649450746,
	"iss": "https://trust-anchor.example.eu",
	"sub": "https://intermediate.eidas.example.org",
	"jwks": {
    	"keys": [
        	{
            	"kty": "RSA",
            	"n": "5s4qi …",
            	"e": "AQAB",
            	"kid": "em3cmnZgHIYFsQ090N6B3Op7LAAqj8rghMhxGmJstqg",
       "x5c": ["..."]
        	}
    	]
	},
	"trust_marks": [
    	{
        	"id": "https://trust-anchor.example.eu/federation_entity/that-profile",
        	"trust_mark": "eyJhb …"
    	}
	]
}

# the ta publishes the intermediate public key
ta_es["jwks"]['keys'][0] = intermediate_jwk.serialize()


leaf_signer = JWS(leaf_ec, alg="ES256", typ="application/entity-statement+jwt")
leaf_ec_signed = leaf_signer.sign_compact([leaf_jwk])

intermediate_signer = JWS(intermediate_es, alg="ES256", typ="application/entity-statement+jwt")
intermediate_es_signed = intermediate_signer.sign_compact([intermediate_jwk])

ta_signer = JWS(ta_es, alg="ES256", typ="application/entity-statement+jwt")
ta_es_signed = ta_signer.sign_compact([ta_jwk])

trust_chain = [
	leaf_ec_signed,
	intermediate_es_signed,
	ta_es_signed
]
