from datetime import timezone, datetime
import uuid

from pydantic import BaseModel
from pyeudiw.openid4vp.utils import detect_flow_typ
from satosa.context import Context


#TODO: validate entity
class OpenId4VCIEntity(BaseModel):
  document_id: str
  creation_date: str
  state: str
  session_id: str
  remote_flow_typ: str
  request_uri_part: str
  finalized: False
  internal_response: None

  @staticmethod
  def new_entity(context: Context, request_uri_part: str):
    return OpenId4VCIEntity(
        document_id = str(uuid.uuid4()),
        creation_date = datetime.now(tz=timezone.utc),
        request_uri_part = request_uri_part,
        state=str(uuid.uuid4()),
        session_id=context.state["SESSION_ID"],
        remote_flow_typ=detect_flow_typ(context).value
    )