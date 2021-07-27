# coding:utf-8

from base.util.byte_types import hexstr_to_bytes
from blspy import G1Element, PrivateKey, G2Element, AugSchemeMPL
from base.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from base.consensus.coinbase import create_puzzlehash_for_pk
from words.mnemonic import generate_mnemonic, mnemonic_to_seed


address_prefix = 'xch'


def create_address_by_pk(pk: str) -> str:
    return encode_puzzle_hash(
        create_puzzlehash_for_pk(
            G1Element.from_bytes(hexstr_to_bytes(pk))
        ),
        address_prefix
    )


def pk2_puzzle_hash(pk: str) -> str:
    return create_puzzlehash_for_pk(
        G1Element.from_bytes(hexstr_to_bytes(pk))
    ).hex()


def puzzle_hash_2address(puzzle_hash: str) -> str:
    return encode_puzzle_hash(
        hexstr_to_bytes(puzzle_hash),
        address_prefix
    )


def address2_puzzle_hash(xch_address: str) -> str:
    return decode_puzzle_hash(xch_address).hex()


def create_address(password: str = ""):
    mnemonic = generate_mnemonic()
    seed = mnemonic_to_seed(mnemonic, password)
    key = AugSchemeMPL.key_gen(seed)
    address = create_address_by_pk(bytes(key.get_g1()).hex())
    public_key = bytes(key.get_g1()).hex()
    private_key = bytes(key).hex()
    return {
        "mnemonic": mnemonic,
        "address": address,
        "public_key": public_key,
        "private_key": private_key,
    }


if __name__ == "__main__":
    print(create_address())