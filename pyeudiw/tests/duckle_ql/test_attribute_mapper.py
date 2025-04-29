import pytest

from pyeudiw.duckle_ql.attribute_mapper import map_attribute
from pyeudiw.duckle_ql.credential import DC_SD_JWT_FORMAT, MSO_MDOC_FORMAT


def test_map_attribute_success():
    data_list = [
        {
            'credential_format': MSO_MDOC_FORMAT,
            'doctype': 'org.iso.18013.5.1.mDL',
            'namespaces': {
                'org.iso.18013.5.1': {
                    'given_name': 'Mario',
                    'family_name': 'Rossi',
                    'resident_country': 'Italy',
                    'resident_address': 'Via Roma 1',
                    'non_disclosed': 'secret'
                }
            }
        },
        {
            'credential_format': MSO_MDOC_FORMAT,
            'doctype': 'org.iso.18013.5.1.mDL',
            'namespaces': {
                'org.iso.18013.5.1': {
                    'resident_country': 'Italy',
                    'resident_address': 'Via Roma 1',
                    'non_disclosed': 'secret'
                }
            }
        },
        {
            'id': 'personal id data',
            'credential_format': DC_SD_JWT_FORMAT,
            'meta': {
                'vct_values': ['https://trust-registry.eid-wallet.example.it/credentials/v1.0/personidentificationdata']
            },
            'claims': [{'path': ['given_name']}, {'path': ['family_name']}, {'path': ['personal_administrative_number']}]
        },
        {
            'id': 'wallet attestation',
            'credential_format': DC_SD_JWT_FORMAT,
            'meta': {
                'vct_values': ['https://itwallet.registry.example.it/WalletAttestation']
            },
            'claims': [{'path': ['wallet_link']}, {'path': ['wallet_name']}]
        }
    ]

    expected = {
        'given_name': 'Mario',
        'family_name': 'Rossi',
        'resident_country': 'Italy',
        'resident_address': 'Via Roma 1',
        'non_disclosed': 'secret'
    }

    result = map_attribute(data_list)
    assert result == expected


def test_map_attribute_conflict():
    data_list = [
        {
            'credential_format': MSO_MDOC_FORMAT,
            'namespaces': {
                'org.iso.18013.5.1': {
                    'given_name': 'Mario'
                }
            }
        },
        {
            'credential_format': MSO_MDOC_FORMAT,
            'namespaces': {
                'org.iso.18013.5.1': {
                    'given_name': 'Luigi'
                }
            }
        }
    ]

    with pytest.raises(ValueError, match="Key conflict: 'given_name' has conflicting values 'Mario' and 'Luigi'"):
        map_attribute(data_list)
