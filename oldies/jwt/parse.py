def _unsafe_decode_part(part: str) -> dict:
    padding_needed = len(part) % 4
    if padding_needed:
        part += "=" * (4 - padding_needed)
    decoded_bytes = base64.urlsafe_b64decode(part)
    return json.loads(decoded_bytes.decode("utf-8"))