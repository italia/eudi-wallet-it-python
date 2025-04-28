from typing import List

from pyeudiw.duckle_ql.credential import DcqlCredential, DcqlQuery, MSO_MDOC_FORMAT


def flat_credentials_mso_mdoc(credentials: List[DcqlCredential]) -> List[DcqlCredential]:
    """
    Flattens a list of DcqlCredential objects, merging credentials with the same
    credential_format, doctype, and namespaces.

    :param credentials: A list of DcqlCredential objects.
    :return: A list of flattened DcqlCredential objects.
    """
    merged_credentials = []
    seen = {}
    for credential in credentials:
        key = (credential.credential_format, credential.doctype) # Modified key
        if key not in seen:
            seen[key] = credential
            merged_credentials.append(credential)
        else:
            existing_credential = seen[key]
            # Merge the namespaces by combining the claims correctly
            for namespace, claims in credential.namespaces.items():
                if namespace in existing_credential.namespaces:
                    existing_claims = existing_credential.namespaces[namespace]  # Get existing claims
                    for claim_name, claim_value in claims.items():
                        existing_claims[claim_name] = claim_value # Correctly merge claim
                else:
                    existing_credential.namespaces[namespace] = claims
    return merged_credentials

def match_credential_mso_mdoc_format(query: DcqlQuery, credentials: list[DcqlCredential]) -> bool:
    for credential in credentials:
        if (
                credential.credential_format == query.format
                and credential.doctype == query.meta.doctype_value
        ):
            all_claims_present = True
            for claim in query.claims:
                namespace = claim.namespace
                claim_name = claim.claim_name
                if (
                        namespace not in credential.namespaces
                        or claim_name not in credential.namespaces[namespace]
                ):
                    all_claims_present = False
                    break

                if claim.values:
                    if claim_name in credential.namespaces[namespace]:
                        claim_values = credential.namespaces[namespace][claim_name]
                        if claim_values and claim_values not in claim.values:
                            all_claims_present = False
                            break

            return all_claims_present

def match_credential(queries: list[DcqlQuery], credentials: list[DcqlCredential]):
    mso_mdoc_queries = list(filter(lambda q: q.format == MSO_MDOC_FORMAT, queries))
    if mso_mdoc_queries:
        for query in mso_mdoc_queries:
            mso_mdoc_credentials = list(filter(lambda c: c.credential_format == MSO_MDOC_FORMAT, credentials))
            if not mso_mdoc_credentials:
                raise ValueError(f"Missing credential in format {MSO_MDOC_FORMAT}")
            if not match_credential_mso_mdoc_format(query, flat_credentials_mso_mdoc(mso_mdoc_credentials)):
                raise ValueError(f"Credential does not match query: {query.id}")
    else:
        raise ValueError(f"Credential does not match format {MSO_MDOC_FORMAT}")

