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