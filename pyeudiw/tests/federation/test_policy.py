
from pyeudiw.federation.policy import (
    do_sub_one_super_add, PolicyError, do_value
)


def test_do_sub_one_super_add_subset_of():
    SUPERIOR = {
        "subset_of": set(["test_a", "test_b"])
    }

    CHILD = {
        "subset_of": set(["test_a", "test_d"])
    }

    policy = do_sub_one_super_add(SUPERIOR, CHILD, "subset_of")
    assert policy == ['test_a']


def test_do_sub_one_super_add_subset_of_fail():
    SUPERIOR = {
        "subset_of": set(["test_a", "test_b"])
    }

    CHILD = {
        "subset_of": set(["test_q", "test_d"])
    }

    try:
        do_sub_one_super_add(SUPERIOR, CHILD, "subset_of")
    except PolicyError:
        return


def test_do_sub_one_super_add_combine_superset_of():
    SUPERIOR = {
        "superset_of": set(["test_a", "test_b"])
    }

    CHILD = {
        "superset_of": set(["test_a", "test_d"])
    }

    policy = do_sub_one_super_add(SUPERIOR, CHILD, "superset_of")
    assert policy == ['test_a']


def test_do_superset_of_fail():
    SUPERIOR = {
        "superset_of": set(["test_a", "test_b"])
    }

    CHILD = {
        "superset_of": set(["test_q", "test_d"])
    }

    try:
        do_sub_one_super_add(SUPERIOR, CHILD, "superset_of")
    except PolicyError:
        return


def test_do_value_superset_of():
    SUPERIOR = {
        "superset_of": set(["test_a", "test_b"])
    }

    CHILD = {
        "superset_of": set(["test_a", "test_b"])
    }

    policy = do_value(SUPERIOR, CHILD, "superset_of")
    assert policy == set(["test_a", "test_b"])


def test_do_value_superset_of_fail():
    SUPERIOR = {
        "superset_of": set(["test_a", "test_b"])
    }

    CHILD = {
        "superset_of": set(["test_q", "test_d"])
    }

    try:
        do_value(SUPERIOR, CHILD, "superset_of")
    except PolicyError:
        return
