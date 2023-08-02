import logging
#from pyeudiw.federation.statements import (
#    get_entity_configurations,
#    EntityStatement,
#)
import urllib.request
from pyeudiw.tools.utils import iat_now
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header
from pyeudiw.federation.schema import is_es

logger = logging.getLogger("pyeudiw.federation")

class TimeValidationError(Exception):
    def __init__(self, message, errors):
        super().__init__(message)
        
class KeyValidationError(Exception):
    def __init__(self, message, errors):
        super().__init__(message)

class StaticTrustChainValidator:
    def __init__(
        self,
        static_trust_chain :list,
        trust_anchor_jwks :list,
        **kwargs,
    ) -> None:
        
        self.static_trust_chain = static_trust_chain
        self.updated_trust_chain = []
        self.trust_anchor_jwks = trust_anchor_jwks
        for k,v in kwargs.items():
            setattr(self, k, v)
    
    def _validate_exp(self, exp):
        if exp < iat_now():
            raise TimeValidationError(f"TA expiried")
        
    def _validate_keys(self, fed_jwks, st_header):
        current_kid = st_header["kid"]
        
        validation_kid = None
        
        for key in fed_jwks:
            if key["kid"] == current_kid:
                validation_kid = key
        
        if validation_kid == None:
            raise KeyValidationError(f"Kid {current_kid} not in chain")
        
    def _validate_single(self, fed_jwks, header, payload):
        try:
            self._validate_keys(fed_jwks, header)
            self._validate_exp(payload["exp"])
        except Exception as e:
            logger.warning(f"Warning: {e}")
            return False
        
        return True
    
    @property
    def is_valid(self):
        exps = []
        
        # start from the last entity statement
        rev_tc = [
            i for i in reversed(
                self.updated_trust_chain or self.static_trust_chain
            )
        ]
        
        # inspect the entity statement kid header to know which 
        # TA's public key to use for the validation
        
        es_payload = unpad_jwt_payload(rev_tc[0])
        es_exp = es_payload["exp"]
        
        # if valid: exps.append(this-exp)
        self._validate_exp(es_exp)
                
        fed_jwks = es_payload["jwks"]["keys"]
                
        # for st in rev_tc[1:]:
        # validate the entire chain taking in cascade using fed_jwks
        # if valid -> update fed_jwks with $st
        
        for st in rev_tc[1:]:
            st_header = unpad_jwt_header(st)
            st_payload = unpad_jwt_payload(st)
            
            if self._validate_single(fed_jwks, st_header, st_payload) == False:
                return False
            
            fed_jwks = st_payload["jwks"]["keys"]
            
        return True
    
    def update(self):
        self.updated_trust_chain = []
                
        for st in self.static_trust_chain:            
            payload = unpad_jwt_payload(st)
            download_url = None
            
            if is_es(payload):
                download_url = payload["source_endpoint"] if payload.get("source_endpoint", None) else payload["iss"] + "fetch"
            else:
                iss = payload["iss"]
                download_url = iss + ".well-known/openid-federation"
            
            contents = urllib.request.urlopen(download_url).read()
            
            self.updated_trust_chain.append(contents)
            
        return self.is_valid
            
        
        
