from pathlib import Path

import pytest

from pyeudiw.sd_jwt.utils.demo_utils import load_yaml_settings
from pyeudiw.sd_jwt.utils.yaml_specification import load_yaml_specification

tc_basedir = Path(__file__).parent / "testcases"


def pytest_generate_tests(metafunc):
    # load all test cases from the subdirectory "testcases" below the current file's directory
    # and generate a test case for each one
    if "testcase" in metafunc.fixturenames:
        testcases = list(tc_basedir.glob("*/specification.yml"))
        metafunc.parametrize(
            "testcase",
            [load_yaml_specification(t) for t in testcases],
            ids=[t.parent.name for t in testcases],
        )


@pytest.fixture
def settings():
    settings_file = tc_basedir / "settings.yml"
    return load_yaml_settings(settings_file)
