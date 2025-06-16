from pymongo.results import UpdateResult

from pyeudiw.openid4vci.storage.entity import OpenId4VCIEntity
from pyeudiw.storage.mongo_storage import MongoStorage


class OpenId4VciStorage(MongoStorage):
    """
    A storage class extending MongoStorage to manage sessions related to OpenID4VCI interactions.

    This class provides methods to initialize, retrieve, and update session data stored in a MongoDB database.
    """

    def __init__(self, conf: dict, url: str, connection_params=None) -> None:
        if connection_params is None:
            connection_params = {}
        super().__init__(conf, url, connection_params)

    def init_session(self, entity: OpenId4VCIEntity) -> str:
        """
        Store a new session entity in the MongoDB collection.

        :param entity: An instance of OpenId4VCIEntity containing session data.
        :return: The document ID assigned to the stored session.
        """
        super().init_session(
            entity.document_id, entity.session_id, entity.state, entity.remote_flow_typ
        )
        return entity.document_id

    def get_by_session_id(self, session_id: str = "") -> OpenId4VCIEntity:
        """
        Retrieve a session entity by its session ID.

        :param session_id: The session ID associated with the entity.
        :return: An instance of OpenId4VCIEntity containing the retrieved data.
        :raises: ValueError if the session is not found or cannot be parsed.
        """
        docs = super().get_by_session_id(session_id)
        return OpenId4VCIEntity(**docs)

    def update_nonce_by_session_id(self, session_id: str, c_nonce: str) -> UpdateResult:
        """
        Update the nonce value of a session based on the session ID.

        :param session_id: The session ID identifying the session document.
        :param c_nonce: The new nonce value to set.
        :return: The result of the update operation.
        :raises: ValueError if the document cannot be updated.
        """
        return self._update(self.get_by_session_id(session_id).document_id, updated_data={
            "nonce": c_nonce
        })

    def update_attributes_by_session_id(self, session_id: str, attributes: dict) -> UpdateResult:
        """
        Update the nonce value of a session based on the session ID.

        :param session_id: The session ID identifying the session document.
        :param attributes: The attributes value to set.
        :return: The result of the update operation.
        :raises: ValueError if the document cannot be updated.
        """
        return self._update(self.get_by_session_id(session_id).document_id, updated_data={
            "attributes": attributes
        })

    def _update(self, document_id: str, updated_data: dict) -> UpdateResult:
        """
        Update a document in the session collection with new data.

        :param document_id: The document ID of the session to update.
        :param updated_data: A dictionary of fields to update.
        :return: The result of the update operation.
        :raises: ValueError if the update operation does not affect exactly one document.
        """
        self._connect()
        update_result: UpdateResult = self.sessions.update_one(
            {"document_id": document_id},
            {
                "$set": updated_data
            },
        )
        if update_result.matched_count != 1 or update_result.modified_count != 1:
            raise ValueError(f"Cannot update document {document_id}.")

        return update_result
