import pytest
import io

from pyeudiw.sd_jwt.utils.yaml_specification import _yaml_load_specification
from pyeudiw.sd_jwt.common import SDObj

YAML_TESTCASES = [
    """
user_claims:
  is_over:
    !sd "13": True
    !sd "18": False
    !sd "21": False
""",
    """
yaml_parsing: |
    Multiline text
    is also supported
"""
]

YAML_TESTCASES_EXPECTED = [
    {
        "user_claims": {
            "is_over": {
                SDObj("13"): True,
                SDObj("18"): False,
                SDObj("21"): False,
            }
        }
    },
    {
        "yaml_parsing": "Multiline text\nis also supported\n"
    }
]


@pytest.mark.parametrize(
    "yaml_testcase,expected", zip(YAML_TESTCASES, YAML_TESTCASES_EXPECTED)
)
def test_parsing_yaml(yaml_testcase, expected):
    # load_yaml_specification expects a file-like object, so we wrap the string in an io.StringIO

    yaml_testcase = io.StringIO(yaml_testcase)
    result = _yaml_load_specification(yaml_testcase)
    assert result == expected
