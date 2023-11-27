import pytest
from datetime import datetime
from pyeudiw.tests.settings import CONFIG
from pyeudiw.trust import TrustEvaluationHelper
from pyeudiw.storage.db_engine import DBEngine, TrustType
from pyeudiw.tests.federation.base import trust_chain_issuer
from pyeudiw.tests.x509.test_x509 import gen_chain, chain_to_pem


class TestTrustEvaluationHelper:
    @pytest.fixture(autouse=True)
    def create_engine_instance(self):
        self.engine = DBEngine(CONFIG['storage'])

    def test_evaluation_method_federation(self):
        teh = TrustEvaluationHelper(self.engine, {}, "", **{"trust_chain": trust_chain_issuer})

        assert teh.federation == teh._get_evaluation_method()

    def test_chain_validity_federation(self):
        teh = TrustEvaluationHelper(self.engine, {}, "", **{"trust_chain": trust_chain_issuer})

        assert teh.evaluation_method() == True

    def test_evaluation_method_x509(self):
        teh = TrustEvaluationHelper(self.engine, {}, "", **{"trust_chain": gen_chain()})

        assert teh.x509 == teh._get_evaluation_method()

    def test_chain_validity_x509(self):
        date = datetime.now()

        x509_chain = gen_chain()

        self.engine.add_trust_anchor(
            "leaf.example.org", chain_to_pem(x509_chain), date, TrustType.X509)

        teh = TrustEvaluationHelper(self.engine, {}, "", **{"trust_chain": x509_chain})

        assert teh.evaluation_method() == True

    def test_chain_invalid_x509(self):
        date = datetime.now()
        x509_chain = gen_chain()
        x509_chain[1] = x509_chain[0]

        self.engine.add_trust_anchor(
            "leaf.example.org", chain_to_pem(x509_chain), date, TrustType.X509)

        teh = TrustEvaluationHelper(self.engine, {}, "", **{"trust_chain": x509_chain})

        assert teh.evaluation_method() == False

    def test_get_trusted_jwk(self):
        teh = TrustEvaluationHelper(self.engine, {}, "", **{"trust_chain": trust_chain_issuer})

        trusted_jwks = teh.get_trusted_jwks("openid_credential_issuer")

        assert trusted_jwks
        assert len(trusted_jwks) == 1