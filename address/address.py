# coding:utf-8

from typing import List, Optional, Tuple
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


def derive_path(sk: PrivateKey, path: List[int]) -> PrivateKey:
    for index in path:
        sk = AugSchemeMPL.derive_child_sk(sk, index)
    return sk


def create_address(password: str = "", index: int = 1):
    mnemonic = generate_mnemonic()
    seed = mnemonic_to_seed(mnemonic, password)
    key = AugSchemeMPL.key_gen(seed)
    path = [12381, 8444, 2, index]
    child = derive_path(key, path)
    # g_child = AugSchemeMPL.derive_child_sk(child, 0)
    address = create_address_by_pk(bytes(child.get_g1()).hex())
    public_key = bytes(key.get_g1()).hex()
    private_key = bytes(key).hex()
    # child_puk = bytes(child.get_g1()).hex()
    # child_prk = bytes(child).hex()
    return {
        "mnemonic": mnemonic,
        "address": address,
        "public_key": public_key,
        "private_key": private_key,
        # "child_puk": child_puk,
        # "child_prk": child_prk,
    }


if __name__ == "__main__":
    print(create_address())