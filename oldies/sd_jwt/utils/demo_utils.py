def print_repr(values: Union[str, list], nlines=2):
    value = "\n".join(values) if isinstance(values, (list, tuple)) else values
    _nlines = "\n" * nlines if nlines else ""
    print(value, end=_nlines)


def print_decoded_repr(value: str, nlines=2):
    seq = []
    for i in value.split("."):
        try:
            padded = f"{i}{'=' * divmod(len(i),4)[1]}"
            seq.append(f"{base64.urlsafe_b64decode(padded).decode()}")
        except Exception as e:
            logging.debug(f"{e} - for value: {i}")
            seq.append(i)
    _nlines = "\n" * nlines if nlines else ""
    print("\n.\n".join(seq), end=_nlines)