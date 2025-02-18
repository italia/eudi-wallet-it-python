def _is_same_device_flow(request_session: dict, context: Context) -> bool:
    initiating_session_id: str | None = request_session.get("session_id", None)
    if initiating_session_id is None:
        raise ValueError(
            "invalid session storage information: missing [session_id]"
        )
    current_session_id: str | None = context.state.get("SESSION_ID", None)
    if current_session_id is None:
        raise ValueError("missing session id in wallet authorization response")
    return initiating_session_id == current_session_id

def _parse_http_request(self, context: Context) -> dict:
    """Parse the http layer of the request to extract the dictionary data.

    :param context: the satosa context containing, among the others, the details of the HTTP request
    :type context: satosa.Context

    :return: a dictionary containing the request data
    :rtype: dict

    :raises BadRequestError: when request paramets are in a not processable state; the expected handling is returning 400
    """
    if (
        http_method := context.request_method.lower()
    ) != ResponseHandler._SUPPORTED_RESPONSE_METHOD:
        raise BadRequestError(f"HTTP method [{http_method}] not supported")

    if (
        content_type := context.http_headers["HTTP_CONTENT_TYPE"]
    ) != ResponseHandler._SUPPORTED_RESPONSE_CONTENT_TYPE:
        raise BadRequestError(f"HTTP content type [{content_type}] not supported")

    _endpoint = f"{self.server_url}{context.request_uri}"
    
    if self.config["metadata"].get("response_uris", None):
        if _endpoint not in self.config["metadata"]["response_uris"]:
            raise BadRequestError("response_uri not valid")

    return context.request