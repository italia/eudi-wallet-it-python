    def _handle_x509_pem(self):
        trust_anchor_eid = self.trust_anchor or get_issuer_from_x5c(
            self.trust_chain)
        _is_valid = False

        if not trust_anchor_eid:
            raise UnknownTrustAnchor(
                "Unknown Trust Anchor: can't find 'iss' in the "
                "first entity statement"
            )

        try:
            trust_anchor = self.storage.get_trust_anchor(trust_anchor_eid)
        except EntryNotFound:
            raise UnknownTrustAnchor(
                f"Unknown Trust Anchor: '{trust_anchor_eid}' is not "
                "a recognizable Trust Anchor."
            )

        pem = trust_anchor['x509'].get('pem')

        if pem is None:
            raise MissingTrustType(
                f"Trust Anchor: '{trust_anchor_eid}' has no x509 trust entity"
            )

        try:
            _is_valid = verify_x509_anchor(pem)
        except Exception as e:
            raise InvalidAnchor(
                f"Anchor verification raised the following exception: {e}"
            )

        if not self.is_trusted and trust_anchor['federation'].get("chain", None) is not None:
            self._handle_federation_chain()

        self.is_trusted = _is_valid
        return _is_valid


    def x509(self) -> bool:
        self.is_valid = self._handle_x509_pem()
        return self.is_valid
