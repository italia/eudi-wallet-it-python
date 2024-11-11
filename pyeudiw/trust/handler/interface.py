from pyeudiw.trust.model.trust_source import TrustSourceData

class TrustHandlerInterface:
    def extract_and_update_trust_materials(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        """
        Extract the trust material of a certain issuer using a trust handler implementation.

        :param issuer: The issuer
        :type issuer: str
        :param trust_source: The trust source to update
        :type trust_source: TrustSourceData

        :returns: The updated trust source
        :rtype: TrustSourceData
        """
        raise NotImplementedError

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        """
        Get the metadata of a certain issuer if is needed by the specifics.

        :param issuer: The issuer
        :type issuer: str
        :param trust_source: The trust source to update
        :type trust_source: TrustSourceData
        
        :returns: The updated trust source
        :rtype: TrustSourceData
        """

        raise NotImplementedError

    @property
    def name(self) -> str:
        """
        Return the name of the trust handler.

        :returns: The name of the trust handler
        :rtype: str
        """
        return self.__class__.__name__