
from pyeudiw.tools.utils import iat_now, exp_from_now
from pyeudiw.federation.schema import is_es, is_ec

NOW = iat_now()
EXP = exp_from_now(5)

ta_es = {
    "exp": EXP,
    "iat": NOW,
    "iss": "https://trust-anchor.example.eu",
    "sub": "https://intermediate.eidas.example.org",
    'jwks': {"keys": []},
    "source_endpoint": "https://rp.example.it"
}

ta_ec = {
    "exp": EXP,
    "iat": NOW,
    'iss': 'https://registry.eidas.trust-anchor.example.eu/',
    'sub': 'https://registry.eidas.trust-anchor.example.eu/',
    'jwks': {"keys": []},
    'metadata': {'federation_entity': {'organization_name': 'example TA',
                                       'contacts': ['tech@eidas.trust-anchor.example.eu'],
                                       'homepage_uri': 'https://registry.eidas.trust-anchor.example.eu/',
                                       'logo_uri': 'https://registry.eidas.trust-anchor.example.eu/static/svg/logo.svg',
                                       'federation_fetch_endpoint': 'https://registry.eidas.trust-anchor.example.eu/fetch/',
                                       'federation_resolve_endpoint': 'https://registry.eidas.trust-anchor.example.eu/resolve/',
                                       'federation_list_endpoint': 'https://registry.eidas.trust-anchor.example.eu/list/',
                                       'federation_trust_mark_status_endpoint': 'https://registry.eidas.trust-anchor.example.eu/trust_mark_status/'}},
    'trust_marks_issuers': {'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/public/': ['https://registry.spid.eidas.trust-anchor.example.eu/',
                                                                                                            'https://public.intermediary.spid.org/'],
                            'https://registry.eidas.trust-anchor.example.eu/openid_relying_party/private/': ['https://registry.spid.eidas.trust-anchor.example.eu/',
                                                                                                             'https://private.other.intermediary.org/']},
    'constraints': {'max_path_length': 1}}


def test_is_es():
    assert is_es(ta_es)


def test_is_es_false():
    assert not is_es(ta_ec)


def test_is_ec():
    assert is_ec(ta_ec)


def test_is_ec_false():
    assert not is_ec(ta_es)
