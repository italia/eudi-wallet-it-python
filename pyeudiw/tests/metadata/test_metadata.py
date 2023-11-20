import pytest
from pyeudiw.metadata.policy import combine
from pyeudiw.metadata.policy import combine_claim_policy
from pyeudiw.metadata.policy import TrustChainPolicy
from pyeudiw.metadata.exceptions import PolicyError

__author__ = "Roland Hedberg"
__license__ = "Apache 2.0"
__version__ = ""

SIMPLE = [
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y', 'Z']},
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y']}),
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y', 'Z']},
        {"subset_of": ['X', 'Y', 'W']},
        {"subset_of": ['X', 'Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['A', 'X', 'Y', 'Z']},
        {"subset_of": ['X', 'Y', 'W']},
        {"subset_of": ['X', 'Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['Y', 'Z']},
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['Z', 'Y']},
        {"subset_of": ['Y']}
    ),
    (
        "SUBSET_OF",
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['Z', 'W']},
        PolicyError
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['X', 'Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y', 'W']},
        {"superset_of": ['X', 'Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['A', 'X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y', 'W']},
        {"superset_of": ['X', 'Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['Y', 'Z']},
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['Z', 'Y']},
        {"superset_of": ['Y']}
    ),
    (
        "SUPERSET_OF",
        {"superset_of": ['X', 'Y']},
        {"superset_of": ['Z', 'W']},
        PolicyError
    ),

    (
        "ONE_OF",
        {"one_of": ['X', 'Y', 'Z']},
        {"one_of": ['X', 'Y']},
        {"one_of": ['X', 'Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['X', 'Y', 'Z']},
        {"one_of": ['X', 'Y', 'W']},
        {"one_of": ['X', 'Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['A', 'X', 'Y', 'Z']},
        {"one_of": ['X', 'Y', 'W']},
        {"one_of": ['X', 'Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['Y', 'Z']},
        {"one_of": ['X', 'Y']},
        {"one_of": ['Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['X', 'Y']},
        {"one_of": ['Z', 'Y']},
        {"one_of": ['Y']}
    ),
    (
        "ONE_OF",
        {"one_of": ['X', 'Y']},
        {"one_of": ['Z', 'W']},
        PolicyError
    ),
    (
        "ADD",
        {"add": "X"},
        {"add": "B"},
        {"add": ["X", "B"]}
    ),
    (
        "ADD",
        {"add": "X"},
        {"add": "X"},
        {"add": "X"}
    ),
    (
        "VALUE",
        {"value": "X"},
        {"value": "B"},
        PolicyError
    ),
    (
        "VALUE",
        {"value": "X"},
        {"value": "X"},
        {"value": "X"}
    ),
    (
        "VALUE",
        {"value": ["X", "Y"]},
        {"value": ["X", "Z"]},
        PolicyError
    ),
    (
        "DEFAULT",
        {"default": "X"},
        {"default": "B"},
        PolicyError
    ),
    (
        "DEFAULT",
        {"default": ["X", "B"]},
        {"default": ["B", "Y"]},
        PolicyError
    ),
    (
        "DEFAULT",
        {"default": "X"},
        {"default": "X"},
        {"default": "X"}
    ),
    (
        "ESSENTIAL",
        {"essential": True},
        {"essential": False},
        PolicyError
    ),
    (
        "ESSENTIAL",
        {"essential": False},
        {"essential": True},
        {"essential": True}
    ),
    (
        "ESSENTIAL",
        {"essential": True},
        {"essential": True},
        {"essential": True}
    ),
    (
        "ESSENTIAL",
        {"essential": False},
        {"essential": False},
        {"essential": False}
    )
]

COMPLEX = [
    (
        {"essential": False},
        {"default": 'A'},
        {"essential": False, "default": 'A'}
    ),
    (
        {"essential": True},
        {"default": 'A'},
        {"essential": True, "default": 'A'}
    ),
    (
        {"essential": False, "default": 'A'},
        {"default": 'A', "essential": True},
        {"essential": True, "default": 'A'}
    ),
    (
        {"essential": True, "default": 'A'},
        {"default": 'B', "essential": True},
        PolicyError
    ),
    (
        {"essential": False},
        {"subset_of": ['B']},
        {"essential": False, "subset_of": ['B']}
    ),
    (
        {"subset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['Y', 'Z']},
        {"subset_of": ['X', 'Y', 'Z'], "superset_of": ['Y', 'Z']}
    ),
    (
        {"superset_of": ['Y', 'Z']},
        {"subset_of": ['X', 'Y']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"superset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y'], "superset_of": ['X', 'Y']}
    ),
    (
        {"superset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y']},
        {"subset_of": ['X', 'Y'], "superset_of": ['X', 'Y']}
    ),
    (
        {"subset_of": ['X', 'Y', 'Z']},
        {"superset_of": ['Y', 'A']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y', ]},
        {"superset_of": ['X', 'Y', 'A']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"default": ['X']},
        {"subset_of": ['X', 'Y'], "default": ['X']}
    ),
    (
        {"superset_of": ['X', 'Y']},
        {"default": ['X', 'Y', 'Z']},
        {"superset_of": ['X', 'Y'], "default": ['X', 'Y', 'Z']}
    ),
    (
        {"one_of": ['X', 'Y']},
        {"default": 'X'},
        {"one_of": ['X', 'Y'], "default": 'X'}
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"default": ['X', 'Z']},
        PolicyError
    ),
    (
        {"subset_of": ['X', 'Y']},
        {"one_of": ['X', 'Y']},
        PolicyError
    ),
    (
        {"superset_of": ['X', 'Y']},
        {"default": ['X', 'Z']},
        PolicyError
    ),
    (
        {"one_of": ['X', 'Y']},
        {"default": 'Z'},
        PolicyError
    )
]

def assert_equal(val1, val2):
    assert set(val1.keys()) == set(val2.keys())

    for key, attr in val1.items():
        if isinstance(attr, bool):
            return attr == val2[key]
        elif isinstance(attr, list):
            return set(attr) == set(val2[key])
        else:
            return attr == val2[key]


@pytest.mark.parametrize("typ, superior, subordinate, result", SIMPLE)
def test_simple_policy_combinations(typ, superior, subordinate, result):
    if result in [PolicyError]:
        with pytest.raises(result):
            combine_claim_policy(superior, subordinate)
    else:
        cp = combine_claim_policy(superior, subordinate)
        assert assert_equal(cp, result)


@pytest.mark.parametrize("superior, subordinate, result", COMPLEX)
def test_complex_policy_combinations(superior, subordinate, result):
    if result in [PolicyError]:
        with pytest.raises(result):
            combine_claim_policy(superior, subordinate)
    else:
        cp = combine_claim_policy(superior, subordinate)
        assert assert_equal(cp, result)


FED = {
    "scopes": {
        "subset_of": ["openid", "eduperson", "phone"],
        "superset_of": ["openid"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384", "ES512"],
        "default": "ES256"
    },
    "contacts": {
        "add": "helpdesk@federation.example.org"},
    "application_type": {"value": "web"}
}

ORG = {
    "scopes": {
        "subset_of": ["openid", "eduperson", "address"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"},
    "contacts": {
        "add": "helpdesk@org.example.org"},
}

RES = {
    "scopes": {
        "subset_of": ["openid", "eduperson"],
        "superset_of": ["openid"],
        "default": ["openid", "eduperson"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"},
    "contacts": {
        "add": ["helpdesk@federation.example.org",
                "helpdesk@org.example.org"]},
    "application_type": {
        "value": "web"}
}


def test_combine_policies():
    res = combine({'metadata_policy': FED, 'metadata': {}},
                  {'metadata_policy': ORG, 'metadata': {}})

    assert set(res['metadata_policy'].keys()) == set(RES.keys())

    for claim, policy in res['metadata_policy'].items():
        assert set(policy.keys()) == set(RES[claim].keys())
        assert assert_equal(policy, RES[claim])


RP = {
    "contacts": ["rp_admins@cs.example.com"],
    "redirect_uris": ["https://cs.example.com/rp1"],
    "response_types": ["code"]
}

FED1 = {
    "scopes": {
        "superset_of": ["openid", "eduperson"],
        "default": ["openid", "eduperson"]
    },
    "response_types": {
        "subset_of": ["code", "code id_token"]},
    "id_token_signed_response_alg": {
        "one_of": ["ES256", "ES384"],
        "default": "ES256"}
}

ORG1 = {
    "contacts": {
        "add": "helpdesk@example.com"},
    "logo_uri": {
        "one_of": ["https://example.com/logo_small.jpg",
                   "https://example.com/logo_big.jpg"],
        "default": "https://example.com/logo_small.jpg"
    },
    "policy_uri": {
        "value": "https://example.com/policy.html"},
    "tos_uri": {
        "value": "https://example.com/tos.html"}
}

RES1 = {
    "contacts": ["rp_admins@cs.example.com", "helpdesk@example.com"],
    "logo_uri": "https://example.com/logo_small.jpg",
    "policy_uri": "https://example.com/policy.html",
    "tos_uri": "https://example.com/tos.html",
    "scopes": ["openid", "eduperson"],
    "response_types": ["code"],
    "redirect_uris": ["https://cs.example.com/rp1"],
    "id_token_signed_response_alg": "ES256"
}


def test_apply_policies():
    comb_policy = combine({'metadata_policy': FED1, 'metadata': {}},
                          {'metadata_policy': ORG1, 'metadata': {}})

    res = TrustChainPolicy().apply_policy(RP, comb_policy)

    assert set(res.keys()) == set(RES1.keys())

    for claim, value in res.items():
        if isinstance(value, list):
            if isinstance(RES1[claim], list):
                assert set(value) == set(RES1[claim])
            else:
                assert set(value) == {RES1[claim]}
        else:
            if isinstance(RES1[claim], list):
                assert {value} == set(RES1[claim])
            else:
                assert value == RES1[claim]


@pytest.mark.parametrize("policy, metadata, result",
                         [
                             (
                                     [{
                                         'metadata': {'B': 123},
                                         'metadata_policy': {
                                             "A": {"subset_of": ['a', 'b']}
                                         }},
                                         {
                                             'metadata': {'C': 'foo'},
                                             'metadata_policy': {
                                                 "A": {"subset_of": ['a']}
                                             }
                                         }
                                     ],
                                     {
                                         "A": ['a', 'b', 'e'],
                                         "C": 'foo'
                                     },
                                     {
                                         'A': ['a'],
                                         'B': 123,
                                         'C': 'foo'
                                     }
                             )
                         ])
def test_combine_metadata_and_metadata_policy_OK(policy, metadata, result):
    comb_policy = policy[0]
    for pol in policy[1:]:
        comb_policy = combine(comb_policy, pol)

    res = TrustChainPolicy().apply_policy(metadata, comb_policy)
    assert res == result


# 1 a subordinate can not change something a superior has set
@pytest.mark.parametrize("policy",
                         [
                             [
                                 {
                                     'metadata': {'B': 123},
                                     'metadata_policy': {
                                         "A": {"subset_of": ['a', 'b']}
                                     }
                                 },
                                 {
                                     'metadata': {'B': 'foo'},
                                     'metadata_policy': {
                                         "A": {"subset_of": ['a']}
                                     }
                                 }
                             ],
[
                                 {
                                     'metadata': {'B': 123},
                                 },
                                 {
                                     'metadata_policy': {
                                         "B": {"subset_of": [12, 6]}
                                     }
                                 }
                             ]
                         ])
def test_combine_metadata_and_metadata_policy_NOT_OK(policy):
    with pytest.raises(PolicyError):
        combine(policy[0], policy[1])

POLICY_1 = {
    "scopes": {
        "superset_of": ["openid", "eduperson"],
        "subset_of": ["openid", "eduperson"]
    }
}

POLICY_2 = {
    "response_types": {
        "subset_of": ["code", "code id_token"],
        "superset_of": ["code", "code id_token"]
    }
}

ENT = {
    "contacts": ["rp_admins@cs.example.com"],
    "redirect_uris": ["https://cs.example.com/rp1"],
    "response_types": ["code", "code id_token", "id_token"],
    "scopes": ["openid", "eduperson", "email", "address"]
}

def test_set_equality():
    comb_policy = combine({'metadata_policy': POLICY_1, 'metadata': {}},
                          {'metadata_policy': POLICY_2, 'metadata': {}})

    res = TrustChainPolicy().apply_policy(ENT, comb_policy)

    assert set(res['scopes']) == {"openid", "eduperson"}
    assert set(res['response_types']) == {"code", "code id_token"}