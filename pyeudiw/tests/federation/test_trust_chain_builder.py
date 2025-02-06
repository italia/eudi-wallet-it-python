from unittest.mock import patch

from pyeudiw.federation.statements import EntityStatement, get_entity_configurations
from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.tests.settings import httpc_params

from .base import leaf_wallet, ta_ec
from .mocked_response import EntityResponseWithIntermediate


@patch("requests.get", return_value=EntityResponseWithIntermediate())
def test_trust_chain_valid_with_intermediaries(self, mocker):

    jwt = get_entity_configurations([ta_ec["sub"]], httpc_params=httpc_params)[0]
    trust_anchor_ec = EntityStatement(jwt, httpc_params=httpc_params)
    trust_anchor_ec.validate_by_itself()

    trust_chain = TrustChainBuilder(
        subject=leaf_wallet["sub"],
        trust_anchor=trust_anchor_ec.sub,
        trust_anchor_configuration=trust_anchor_ec,
        httpc_params=httpc_params,
    )

    trust_chain.start()
    trust_chain.apply_metadata_policy()

    assert trust_chain.is_valid
    assert trust_chain.final_metadata
    assert len(trust_chain.trust_path) == 3
