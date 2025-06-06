import uuid
from datetime import timezone, datetime
from typing import List, Optional

from pydantic import BaseModel, Field
from satosa.context import Context

from pyeudiw.openid4vci.models.auhtorization_detail import AuthorizationDetail
from pyeudiw.openid4vci.models.par_request import ParRequest
from pyeudiw.openid4vp.utils import detect_flow_typ


class OpenId4VCIEntity(BaseModel):
  document_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
  creation_date: float = Field(default_factory=lambda: datetime.now(tz=timezone.utc).timestamp())
  state: str
  client_id: str
  code_challenge: str
  code_challenge_method: str
  session_id: str
  remote_flow_typ: str
  request_uri_part: str
  redirect_uri: str
  authorization_details: List[AuthorizationDetail] = None
  c_nonce: str = None
  finalized: bool = False
  attributes: Optional[dict] = None

  @staticmethod
  def new_entity(context: Context, request_uri_part: str, par_request: ParRequest):
    return OpenId4VCIEntity(
        request_uri_part = request_uri_part,
        state=par_request.state,
        session_id=context.state["SESSION_ID"],
        remote_flow_typ=detect_flow_typ(context).value,
        client_id = par_request.client_id,
        code_challenge = par_request.code_challenge,
        code_challenge_method = par_request.code_challenge_method,
        redirect_uri=par_request.redirect_uri,
        authorization_details=par_request.authorization_details
    )