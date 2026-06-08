"""Tests for CredentialStorage status-list index allocation.

Covers two concerns:

* **Correctness / round-trip** — the index allocated at issuance (``incremental_id``,
  advertised as ``idx`` in the credential's ``status_list`` claim) must point to the
  exact bit a Relying Party reads back from the published status list.
* **Concurrency** — parallel issuers must never receive the same index. Allocation
  relies on an atomic MongoDB ``findAndModify`` (``$inc``); these tests simulate that
  atomicity with a lock-backed fake so the behaviour can be asserted without a real DB.
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pymongo
import pytest
from pymongo.errors import DuplicateKeyError

from pyeudiw.status_list import array_to_bitstring_v1
from pyeudiw.status_list.helper import StatusListTokenHelper

# Optional inline credentials (``username:password@``) for a local authenticated
# MongoDB; defaults to empty (unauthenticated), matching the rest of the suite.
# See README / docs: PYEUDIW_MONGO_TEST_AUTH_INLINE.
_MONGO_URL = (
    f"mongodb://{os.getenv('PYEUDIW_MONGO_TEST_AUTH_INLINE', '')}"
    "localhost:27017/?timeoutMS=15000"
)
from pyeudiw.storage.credential_storage import CredentialStorage


class _FakeAtomicCounter:
    """Models MongoDB's atomic findAndModify ``$inc`` on a single counter document."""

    def __init__(self) -> None:
        self._seq: dict = {}
        self._lock = threading.Lock()

    def find_one_and_update(self, query, update, upsert=False, return_document=None):
        with self._lock:
            _id = query["_id"]
            self._seq[_id] = self._seq.get(_id, 0) + update["$inc"]["seq"]
            return {"_id": _id, "seq": self._seq[_id]}


class _FakeCursor:
    def __init__(self, docs: list[dict]) -> None:
        self._docs = docs

    def sort(self, field: str, direction: int = pymongo.ASCENDING):
        return sorted(
            self._docs,
            key=lambda d: d[field],
            reverse=(direction == pymongo.DESCENDING),
        )


class _FakeCredentials:
    """In-memory credentials collection enforcing the unique incremental_id index."""

    def __init__(self) -> None:
        self.docs: list[dict] = []
        self._lock = threading.Lock()

    def create_index(self, *args, **kwargs):
        return None

    def insert_one(self, doc: dict):
        with self._lock:
            if any(d["incremental_id"] == doc["incremental_id"] for d in self.docs):
                raise DuplicateKeyError("duplicate incremental_id")
            self.docs.append(dict(doc))

    def update_one(self, query: dict, update: dict):
        with self._lock:
            for d in self.docs:
                if d.get("document_id") == query.get("document_id"):
                    d.update(update["$set"])
                    return d
            return None

    def find(self):
        with self._lock:
            return _FakeCursor([dict(d) for d in self.docs])


class _Store(CredentialStorage):
    """CredentialStorage wired to in-memory fakes, with no real DB connection."""

    def __init__(self, counters, credentials) -> None:
        self.counters = counters
        self.credentials = credentials

    def _connect(self):  # no-op: fakes are injected
        return None


class _Entity:
    def __init__(self, document_id: str, revoked: bool = False) -> None:
        self.document_id = document_id
        self.user_id = "user"
        self.revoked = revoked
        self.incremental_id = 0


def _make_store() -> _Store:
    return _Store(_FakeAtomicCounter(), _FakeCredentials())


def test_next_incremental_id_uses_atomic_findandmodify():
    counters = MagicMock()
    counters.find_one_and_update.return_value = {"seq": 7}
    store = _Store(counters, _FakeCredentials())

    assert store._next_incremental_id() == 7

    args, kwargs = counters.find_one_and_update.call_args
    assert args[0] == {"_id": CredentialStorage._INCREMENTAL_ID_COUNTER}
    assert args[1] == {"$inc": {"seq": 1}}
    assert kwargs["upsert"] is True
    assert kwargs["return_document"] == pymongo.ReturnDocument.AFTER


def test_sequential_allocation_is_monotonic_from_one():
    store = _make_store()
    ids = [store.add_credential_for_user(_Entity(f"doc{i}")) for i in range(5)]
    assert ids == [1, 2, 3, 4, 5]


def test_parallel_allocation_has_no_collisions():
    """Many concurrent issuers must each get a distinct, contiguous index."""
    store = _make_store()
    total = 250

    def worker(i: int) -> int:
        return store.add_credential_for_user(_Entity(f"doc{i}"))

    with ThreadPoolExecutor(max_workers=16) as pool:
        ids = list(pool.map(worker, range(total)))

    assert len(set(ids)) == total
    assert sorted(ids) == list(range(1, total + 1))
    assert len(store.credentials.docs) == total


def test_issuance_to_status_list_roundtrip():
    """idx allocated at issuance maps to the correct bit in the published list."""
    store = _make_store()
    entities = [_Entity(f"doc{i}") for i in range(5)]
    for entity in entities:
        store.add_credential_for_user(entity)

    # Revoke the credentials issued at index 2 and 4.
    store.revoke_credential(entities[1])
    store.revoke_credential(entities[3])

    credentials = store.get_all_sorted_by_incremental_id()
    lst_bytes = array_to_bitstring_v1(credentials, bits=1)
    helper = StatusListTokenHelper(
        header={}, payload={}, bits=1, status_list=lst_bytes
    )

    for credential in credentials:
        expected = 1 if credential["revoked"] else 0
        assert helper.get_status(credential["incremental_id"]) == expected


def test_duplicate_index_is_rejected_by_unique_constraint():
    """The unique index is the safety net if an index were ever reused."""
    store = _make_store()
    store.add_credential_for_user(_Entity("doc0"))
    with pytest.raises(DuplicateKeyError):
        store.credentials.insert_one({"document_id": "dup", "incremental_id": 1})


def test_connect_creates_unique_index_on_incremental_id():
    with patch("pyeudiw.storage.credential_storage.pymongo.MongoClient"):
        store = CredentialStorage(
            {"db_name": "db", "db_credentials_collection": "credentials"},
            _MONGO_URL,
        )
    store.credentials.create_index.assert_any_call("incremental_id", unique=True)
