class BaseDB:
    """
    Interface class for database storage.
    """

    def _connect(self) -> None:
        """
        Connect to the database server.

        :raises ConnectionFailure: if the connection fails.

        :returns: None
        """
        raise NotImplementedError()

    def close(self) -> None:
        """
        Close the connection to the storage.

        :returns: None
        """
        raise NotImplementedError()
