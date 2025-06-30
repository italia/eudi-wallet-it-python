from satosa.context import Context

def get_session_id(context: Context) -> str:
    """
    Extract the session ID from the SATOSA context.
    Args:
        context (Context): The SATOSA context.
    Returns:
        str: The session ID.
    """
    return context.state["SESSION_ID"]