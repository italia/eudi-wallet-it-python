import logging
#from pyeudiw.federation.statements import (
#    get_entity_configurations,
#    EntityStatement,
#)
from pyeudiw.tools.utils import iat_now
from pyeudiw.jwt.utils import unpad_jwt_payload, unpad_jwt_header

logger = logging.getLogger("pyeudiw.federation")

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
            raise Exception(f"TA expiried")
        
    def _validate_keys(self, fed_jwks, st_header):
        current_kid = st_header["kid"]
        
        validation_kid = None
        
        for key in fed_jwks:
            if key["kid"] == current_kid:
                validation_kid = key
        
        if validation_kid == None:
            raise Exception(f"Kid not in chain")                
    
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
        
        #current_kid = es_payload["jwks"]["keys"][0]["kid"]
        
        fed_jwks = es_payload["jwks"]["keys"]
                
        # for st in rev_tc[1:]:
        # validate the entire chain taking in cascade using fed_jwks
        # if valid -> update fed_jwks with $st
        
        for st in rev_tc[1:]:
            st_header = unpad_jwt_header(st)
            st_payload = unpad_jwt_payload(st)
            
            try:
                self._validate_keys(fed_jwks, st_header)
            except Exception as e:
                logger.warning(f"Warning: {e}")
                return False
            
            try:
                self._validate_exp(st_payload["exp"])
            except Exception as e:
                logger.warning(f"Warning: {e}")
                return False
            
            fed_jwks = st_payload["jwks"]["keys"]
            
        return True
    
    def update(self):
        for st in self.static_trust_chain:
            pass
            # if EC -> download again from well-known/openid-federation
            # if ES:
            #   if source_endpoint is available -> take it directly from it
            # else:
            #   get the EC of the issuer and then take the statement from the fetch
            
            # if ok -> self.updated_trust_chain.append(new_es)
        
        return self.is_valid
            
        
        
