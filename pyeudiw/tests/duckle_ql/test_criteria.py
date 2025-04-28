import pytest

from pyeudiw.duckle_ql.credential import DcqlQuery, MSO_MDOC_FORMAT, DcqlMdocCredential
from pyeudiw.duckle_ql.criteria import flat_credentials_mso_mdoc, match_credential_mso_mdoc_format, match_credential


def create_dcql_mdoc_credential(doctype, namespaces=None):
    if namespaces is None:
        namespaces = {}
    return DcqlMdocCredential(
        credential_format=MSO_MDOC_FORMAT,
        doctype=doctype,
        namespaces=namespaces)

def create_dcql_mdoc_query(query_id: str, doctype_value:str, claims=None):
    if claims is None:
        claims = []
    return DcqlQuery.parse({
        "id": query_id,
        "format": MSO_MDOC_FORMAT,
        "meta": {"doctype_value": doctype_value},
        "claims": claims,
    })

class TestCredentialMatching:

    def test_flat_credentials_mso_mdoc_no_duplicates(self):
        creds = [
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim1": "val1"}}),
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns2": {"claim2": "val2"}}),
        ]
        flat_creds = flat_credentials_mso_mdoc(creds)
        assert len(flat_creds) == 1
        assert flat_creds[0].namespaces == {'ns1': {'claim1': 'val1'}, 'ns2': {'claim2': 'val2'}}

    def test_flat_credentials_mso_mdoc_with_duplicates(self):
        creds = [
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim1": "val1"}, "ns3": {"claim3": "val3"}}),
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim2": "val2"}, "ns4": {"claim4": "val4"}}),
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns5": {"claim5": "val5"}}),
        ]
        flat_creds = flat_credentials_mso_mdoc(creds)
        assert len(flat_creds) == 1
        assert flat_creds[0].namespaces == {"ns1": {"claim1": "val1", "claim2": "val2"}, "ns3": {"claim3": "val3"}, "ns4": {"claim4": "val4"}, "ns5": {"claim5": "val5"}}

    def test_match_credential_mso_mdoc_format_success(self):
        mock_query_data = {
            "id": "q1",
            "format":  MSO_MDOC_FORMAT,
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},  # Fornisci un dizionario
            "claims": [
                {"id": "1", "namespace": "ns1", "claim_name": "claim1"},  # Fornisci un dizionario
                {"id": "2", "namespace": "ns2", "claim_name": "claim2", "values": ["val2"]}, # Fornisci un dizionario
            ],
        }
        query = create_dcql_mdoc_query("q1", "org.iso.18013.5.1.mDL", [
            {"id": "1", "namespace": "ns1", "claim_name": "claim1"},
            {"id": "2", "namespace": "ns2", "claim_name": "claim2", "values": ["val2"]},
        ])
        creds = [
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim1": "val1"}, "ns2": {"claim2": "val2"}}),
        ]
        assert match_credential_mso_mdoc_format(query, flat_credentials_mso_mdoc(creds)) is True

    def test_match_credential_mso_mdoc_format_missing_claim(self):
        query = create_dcql_mdoc_query("q1", "org.iso.18013.5.1.mDL",
                                       [{"id": "1", "namespace": "ns1", "claim_name": "missing_claim"}])
        creds = [
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim1": "val1"}}),
        ]
        assert match_credential_mso_mdoc_format(query, flat_credentials_mso_mdoc(creds)) is False

    def test_match_credential_mso_mdoc_format_wrong_value(self):
        query = create_dcql_mdoc_query("q1", "org.iso.18013.5.1.mDL", [
            {"id": "1", "namespace": "ns1", "claim_name": "claim1",  "values": ["wrong_value"]}
        ])
        creds = [
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim1": "val1"}}),
        ]
        assert match_credential_mso_mdoc_format(query, flat_credentials_mso_mdoc(creds)) is False

    def test_match_credential_success(self):
        queries = [
            create_dcql_mdoc_query("q1", "org.iso.18013.5.1.mDL", [
                {"id": "1", "namespace": "ns1", "claim_name": "claim1"}]),
        ]
        creds = [
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim1": "val1"}}),
        ]
        match_credential(queries, creds)
        assert True  # If no exception is raised, the test passes

    def test_match_credential_missing_credential_format(self):
        queries = [
            create_dcql_mdoc_query("q1", "org.iso.18013.5.1.mDL", [
                {"id": "1", "namespace": "ns1", "claim_name": "claim1"}]),
        ]
        creds = [
            DcqlMdocCredential(
                credential_format="test",
                doctype="org.iso.18013.5.1.mDL",
                namespaces={"ns2":{"ns2"}})
        ]
        with pytest.raises(ValueError, match=f"Missing credential in format {MSO_MDOC_FORMAT}"):
            match_credential(queries, creds)

    def test_match_credential_does_not_match_query(self):
        queries = [
            create_dcql_mdoc_query("q1", "org.iso.18013.5.1.mDL", [
                {"id": "1", "namespace": "ns1", "claim_name": "missing_claim"}]),
        ]
        creds = [
            create_dcql_mdoc_credential("org.iso.18013.5.1.mDL", {"ns1": {"claim1": "val1"}}),
        ]
        with pytest.raises(ValueError, match="Credential does not match query: q1"):
            match_credential(queries, creds)