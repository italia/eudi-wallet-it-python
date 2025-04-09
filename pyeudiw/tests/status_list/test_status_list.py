from pyeudiw.status_list.helper import StatusListTokenHelper

def test_statusListHelper():
    helper = StatusListTokenHelper(
        """
        eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.eyJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQWhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3RhdHVzbGlzdHMvMSIsInR0bCI6NDMyMDB9.2RSRdUce0QmRvsbJkt0Hr0Ny5c9Tim2yj43wMFU76xjv9TClW5-B65b9pZSraeoPv6OxTULb4dHiWK0O8oLi6g
        """
    )

    assert helper.get_status(0) == 1
    assert helper.get_status(1) == 0
    assert helper.get_status(2) == 0
    assert helper.get_status(3) == 1
    