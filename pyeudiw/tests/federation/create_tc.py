import json
from pyeudiw.federation.static_trust_chain_builder import (
    LeafInfo, 
    IntermediateInfo, 
    TrustedAnchorInfo, 
    gen_static_trustchain
)

leaf = LeafInfo(
    10, 
    "https://rp.example.org", 
    "https://rp.example.org",
    [{'id': 'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/public/', 'trust_mark': 'eyJh …'}],
    {
        'openid_relying_party': {
            'application_type': 'web',
			'client_id': 'https://rp.example.org/',
			'client_registration_types': ['automatic'],
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
			'contacts': ['tech@example.it']
  			}
   	},
	['https://intermediate.eidas.example.org']
)

intermediate = IntermediateInfo(
    10, 
    "https://intermediate.eidas.example.org", 
    "https://rp.example.org",
    [{'id': 'https://registry.gov.org/intermediate/private/full/','trust_mark': 'eyJh …'}],
    {
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
   	 }
    )

trust = TrustedAnchorInfo(
	10, 
	"https://trust-anchor.example.eu",
	"https://intermediate.eidas.example.org",
	[
    	{
        	"id": "https://trust-anchor.example.eu/federation_entity/that-profile",
        	"trust_mark": "eyJhb …"
    	}
	]
)

trust_chain = gen_static_trustchain(leaf, intermediate, trust)

print(json.dumps(trust_chain))