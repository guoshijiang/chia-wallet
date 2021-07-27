import blspy

from base.types.blockchain_format.sized_bytes import bytes32


def std_hash(b) -> bytes32:
    return bytes32(blspy.Util.hash256(bytes(b)))
