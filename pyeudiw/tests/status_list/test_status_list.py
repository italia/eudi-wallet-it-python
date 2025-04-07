from pyeudiw.status_list.parse import StatusListHelper


def test_statusListHelper():
    helper = StatusListHelper(
        """
        {
            "bits": 1,
            "lst": "eNrbuRgAAhcBXQ"
        }
        """
    )

    assert helper.get_status(0) == 1
    assert helper.get_status(1) == 0
    assert helper.get_status(2) == 0
    assert helper.get_status(3) == 1
    