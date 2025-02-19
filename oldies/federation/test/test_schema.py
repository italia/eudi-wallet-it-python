def test_is_ec():
    is_ec(ta_ec)


def test_is_ec_false():
    try:
        is_ec(ta_es)
    except InvalidEntityConfiguration:
        pass