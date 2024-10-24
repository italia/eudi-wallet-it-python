from pyeudiw.jwt.parse import DecodedJwt, extract_key_identifier
from pyeudiw.tests.jwt import VALID_KID_JWT, VALID_TC_JWT

def test_kid_jwt():
    decoded_jwt = DecodedJwt.parse(VALID_KID_JWT)

    assert decoded_jwt.jwt == VALID_KID_JWT
    assert decoded_jwt.header == {
        "kid": "123456",
        "alg": "HS256",
        "typ": "JWT"
    }
    assert decoded_jwt.payload == {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1516239022
    }
    assert decoded_jwt.signature == "bjM57L1H4gB60_020lKBVvVEhiYCOeEWGzMVEt-XNjc"

def test_tc_jwt():
    decoded_jwt = DecodedJwt.parse(VALID_TC_JWT)

    assert decoded_jwt.jwt == VALID_TC_JWT
    assert decoded_jwt.header == {
        "trust_chain": [
            "eyJhbGciOiJFUzI1NiIsImtpZCI6ImFrNVBOMGR1WjNCeVlVUkVNMWszWm1RM1RFVnlOSEowWTJWVFlUWk1TSFI0VWsxSVExQk9USEpQU1EiLCJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCJ9.eyJleHAiOjE3Mjk5MDQzNDIsImlhdCI6MTcyOTYwNDM0MiwiaXNzIjoiaHR0cHM6Ly9jcmVkZW50aWFsX2lzc3Vlci5leGFtcGxlLm9yZyIsInN1YiI6Imh0dHBzOi8vY3JlZGVudGlhbF9pc3N1ZXIuZXhhbXBsZS5vcmciLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwia2lkIjoiYWs1UE4wZHVaM0J5WVVSRU0xazNabVEzVEVWeU5ISjBZMlZUWVRaTVNIUjRVazFJUTFCT1RISlBTUSIsImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJ4IjoiYjBIcmV6bTVxN1MzUE96ZVNobU9WRjJVV18zbnJvR0RNWnBaeFhlS1B0USIsInkiOiItME9HV0xnOGNoaVItQndPQ2pZeng1Mm1MZlE1b3BSVjVYQ0lVamlpaVRRIn1dfSwibWV0YWRhdGEiOnsib3BlbmlkX2NyZWRlbnRpYWxfaXNzdWVyIjp7Imp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJraWQiOiJNblE0VUdKbmVWUldYMDl5ZWpCUGIyeDBVMU50YUZabFgwMU9PVTlIU0d0MVVpMU5NRE5VV0dsU1JRIiwiYWxnIjoiRVMyNTYiLCJjcnYiOiJQLTI1NiIsIngiOiJ6VHBjNDYxN1dLSUF0UUVXWllYeDFFRjZGOEpnV3ozdHllaHc4MUJ3bG84IiwieSI6ImNITy1DaDZseUUyYmwzMTNrelRhS3JEbC14N3ZXbkU0dkU0VTdWUUF5ak0ifV19fSwiZmVkZXJhdGlvbl9lbnRpdHkiOnsib3JnYW5pemF0aW9uX25hbWUiOiJPcGVuSUQgQ3JlZGVudGlhbCBJc3N1ZXIgZXhhbXBsZSIsImhvbWVwYWdlX3VyaSI6Imh0dHBzOi8vY3JlZGVudGlhbF9pc3N1ZXIuZXhhbXBsZS5vcmcvaG9tZSIsInBvbGljeV91cmkiOiJodHRwczovL2NyZWRlbnRpYWxfaXNzdWVyLmV4YW1wbGUub3JnL3BvbGljeSIsImxvZ29fdXJpIjoiaHR0cHM6Ly9jcmVkZW50aWFsX2lzc3Vlci5leGFtcGxlLm9yZy9zdGF0aWMvbG9nby5zdmciLCJjb250YWN0cyI6WyJ0ZWNoQGNyZWRlbnRpYWxfaXNzdWVyLmV4YW1wbGUub3JnIl19fSwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHBzOi8vaW50ZXJtZWRpYXRlLmVpZGFzLmV4YW1wbGUub3JnIl19.ke58LCSSFvyi6daoaRR346aF3TCn4lCA86GXHhFa09uVE6Gkt6jUJhB8tFlvvdZberhqbvatoGECPCPeCK26Mw",
            "eyJhbGciOiJFUzI1NiIsImtpZCI6Ik9UTnRTRTgyVld4YWFqSjFWbGxXWVRSUGJIWkRZblF5UWxwZmQyVmliRU0yVEVwVGVqRk5WWGRSWnciLCJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCJ9.eyJleHAiOjE3Mjk5MDQzNDIsImlhdCI6MTcyOTYwNDM0MiwiaXNzIjoiaHR0cHM6Ly9pbnRlcm1lZGlhdGUuZWlkYXMuZXhhbXBsZS5vcmciLCJzdWIiOiJodHRwczovL2NyZWRlbnRpYWxfaXNzdWVyLmV4YW1wbGUub3JnIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsImtpZCI6ImFrNVBOMGR1WjNCeVlVUkVNMWszWm1RM1RFVnlOSEowWTJWVFlUWk1TSFI0VWsxSVExQk9USEpQU1EiLCJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2IiwieCI6ImIwSHJlem01cTdTM1BPemVTaG1PVkYyVVdfM25yb0dETVpwWnhYZUtQdFEiLCJ5IjoiLTBPR1dMZzhjaGlSLUJ3T0NqWXp4NTJtTGZRNW9wUlY1WENJVWppaWlUUSJ9XX19.9m1i9qcDLSnpbwiNbGZJozovRTxhF6Qb-EvSZfYNe7csnhY_auTDKDieYoZBfainYGiHM2xw98-wgkygLV7KHw",
            "eyJhbGciOiJFUzI1NiIsImtpZCI6IlZtdzJZbGc0TVRrNWNWbHRiRWxHUkROVk16ZzRUV1pPTTBGUWMwNDFjM0JJZFVkc1lYRm9TbVJLTkEiLCJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCJ9.eyJleHAiOjE3Mjk5MDQzNDIsImlhdCI6MTcyOTYwNDM0MiwiaXNzIjoiaHR0cHM6Ly90cnVzdC1hbmNob3IuZXhhbXBsZS5vcmciLCJzdWIiOiJodHRwczovL2ludGVybWVkaWF0ZS5laWRhcy5leGFtcGxlLm9yZyIsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJraWQiOiJPVE50U0U4MlZXeGFhakoxVmxsV1lUUlBiSFpEWW5ReVFscGZkMlZpYkVNMlRFcFRlakZOVlhkUlp3IiwiYWxnIjoiRVMyNTYiLCJjcnYiOiJQLTI1NiIsIngiOiJrN1RMWVF1SXE5eGNnbGVSd05vYXBGc1Q1eDVjd3B0OExST2d1MEhSZE8wIiwieSI6Ilh4MTBhWnZxeFFrVWxGZUQxdkx1bnhWSndvbGZpUGxqQi1wOXRfY0hLOWMifV19fQ.b7xyGtDp2-ZMWlNBNOjEeUgECL_oP7TQjdHlj2me_Y6js_AeoEhlQ-2eMzWtcuYK4GV8xLGoH7Cln7pFI1OxTg",
            "eyJhbGciOiJFUzI1NiIsImtpZCI6IlZtdzJZbGc0TVRrNWNWbHRiRWxHUkROVk16ZzRUV1pPTTBGUWMwNDFjM0JJZFVkc1lYRm9TbVJLTkEiLCJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCJ9.eyJleHAiOjE3Mjk5MDQzNDIsImlhdCI6MTcyOTYwNDM0MiwiaXNzIjoiaHR0cHM6Ly90cnVzdC1hbmNob3IuZXhhbXBsZS5vcmciLCJzdWIiOiJodHRwczovL3RydXN0LWFuY2hvci5leGFtcGxlLm9yZyIsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJraWQiOiJWbXcyWWxnNE1UazVjVmx0YkVsR1JETlZNemc0VFdaT00wRlFjMDQxYzNCSWRVZHNZWEZvU21SS05BIiwiYWxnIjoiRVMyNTYiLCJjcnYiOiJQLTI1NiIsIngiOiJNQmxWX1NmX1N2aWsxWjJ4ZkxkdjJzNkdHbzZuQlpYMUNpQU9WWV9Ca3N3IiwieSI6ImNLdjEwYTRnT2JVNVluaU10ZU1QQTdpZjhwbDRyZ3hTTXJ0bC1WNDBRVHMifV19LCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJmZWRlcmF0aW9uX2ZldGNoX2VuZHBvaW50IjoiaHR0cHM6Ly90cnVzdC1hbmNob3IuZXhhbXBsZS5vcmcvZmV0Y2giLCJmZWRlcmF0aW9uX3Jlc29sdmVfZW5kcG9pbnQiOiJodHRwczovL3RydXN0LWFuY2hvci5leGFtcGxlLm9yZy9yZXNvbHZlIiwiZmVkZXJhdGlvbl9saXN0X2VuZHBvaW50IjoiaHR0cHM6Ly90cnVzdC1hbmNob3IuZXhhbXBsZS5vcmcvbGlzdCIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiVEEgZXhhbXBsZSIsImhvbWVwYWdlX3VyaSI6Imh0dHBzOi8vdHJ1c3QtYW5jaG9yLmV4YW1wbGUub3JnL2hvbWUiLCJwb2xpY3lfdXJpIjoiaHR0cHM6Ly90cnVzdC1hbmNob3IuZXhhbXBsZS5vcmcvcG9saWN5IiwibG9nb191cmkiOiJodHRwczovL3RydXN0LWFuY2hvci5leGFtcGxlLm9yZy9zdGF0aWMvbG9nby5zdmciLCJjb250YWN0cyI6WyJ0ZWNoQHRydXN0LWFuY2hvci5leGFtcGxlLm9yZyJdfX0sImNvbnN0cmFpbnRzIjp7Im1heF9wYXRoX2xlbmd0aCI6MX19.MbpXfe_NpPgbdWL_zN30SXA88aWrewaJyMWJFAegNrN-8Vy2umcpq3MQph7Yz3ZTawGgi6OGWX7UTDFOWWmf9w"
        ],
        "alg": "HS256",
        "typ": "JWT"
    }

def test_invalid_jwt():
    invalid_jwt = "eyJ"

    try:
        DecodedJwt.parse(invalid_jwt)
        assert False
    except ValueError:
        assert True

def test_extract_key_identifier():
    token_header = {
        "kid": "123456"
    }

    assert extract_key_identifier(token_header) == "123456"

def test_extract_key_identifier_invalid():
    token_header = {
        "invalid": "123456"
    }

    try:
        extract_key_identifier(token_header)
        assert False
    except ValueError:
        assert True


def test_extract_key_identifier_tc():
    #TODO: Implement more accurate tests after implementing get_public_key_from_trust_chain and get_public_key_from_x509_chain
    pass

def test_extract_key_identifier_x5c():
    #TODO: Implement more accurate tests after implementing get_public_key_from_trust_chain and get_public_key_from_x509_chain
    pass
