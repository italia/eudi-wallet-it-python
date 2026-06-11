import cbor2
from pycose.headers import Algorithm
from pycose.keys import EC2Key
from pycose.keys.curves import P256
from pycose.messages import Sign1Message
import pycose.algorithms


def test_cose_sign1_decode_with_cbor2_tagged_tuple():
    """Tagged COSE_Sign1 arrays decoded as tuples (cbor2 >= 6) must decode."""
    key = EC2Key.generate_key(P256)
    msg = Sign1Message(phdr={Algorithm: pycose.algorithms.Es256}, payload=b"payload")
    msg.key = key
    encoded = msg.encode(tag=True, sign=True)

    assert isinstance(cbor2.loads(encoded).value, tuple)

    decoded = Sign1Message.decode(encoded)
    assert isinstance(decoded, Sign1Message)
    assert decoded.payload == b"payload"
    assert decoded.signature
