# coding:utf-8

from typing import (
    List,
    Dict,
    Optional,
    Any,
)

from blspy import G1Element, PrivateKey, G2Element, AugSchemeMPL
from base.util.byte_types import hexstr_to_bytes
from base.consensus.coinbase import create_puzzlehash_for_pk
from base.types.blockchain_format.coin import Coin
from base.types.blockchain_format.program import Program, SerializedProgram
from base.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk
from base.types.blockchain_format.sized_bytes import bytes32
from base.util.ints import uint64
from base.types.coin_solution import CoinSolution
from base.util.hash import std_hash
from base.wallet.puzzles.puzzle_utils import (
    make_assert_coin_announcement,
    make_assert_puzzle_announcement,
    make_assert_my_coin_id_condition,
    make_assert_absolute_seconds_exceeds_condition,
    make_create_coin_announcement,
    make_create_puzzle_announcement,
    make_create_coin_condition,
    make_reserve_fee_condition,
)
from base.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import solution_for_conditions
from base.wallet.puzzles.announcement import Announcement
from base.types.spend_bundle import SpendBundle
from base.wallet.sign_coin_solutions import sign_coin_solutions, unsigned_coin_solutions
from base.consensus.coinbase import DEFAULT_HIDDEN_PUZZLE_HASH
from base.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import calculate_synthetic_secret_key
from address.address import address2_puzzle_hash


def create_signed_tx(sk: str, to_address: str, amount: uint64, fee: int, coins: List) -> dict:
    to_puzzle_hash = address2_puzzle_hash(to_address)
    synthetic = calculate_synthetic_secret_key(
        PrivateKey.from_bytes(hexstr_to_bytes(sk)),
        DEFAULT_HIDDEN_PUZZLE_HASH
    )
    pk = PrivateKey.from_bytes(hexstr_to_bytes(sk)).get_g1()
    transaction = _create_transaction(pk, to_puzzle_hash, amount, fee, coins)
    spend_bundle: SpendBundle = sign_coin_solutions(
        transaction,
        synthetic,
        bytes.fromhex("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"),
        11000000000,
    )
    json_dict = spend_bundle.to_json_dict()
    return json_dict


def sign_tx(sk: str, unsigned_tx: dict, msg_list: List[bytes], pk_list: List[bytes]) -> dict:
    synthetic = calculate_synthetic_secret_key(
        PrivateKey.from_bytes(hexstr_to_bytes(sk)),
        DEFAULT_HIDDEN_PUZZLE_HASH
    )
    signatures: List[G2Element] = []
    for msg in msg_list:
        index = msg_list.index(msg)
        assert bytes(synthetic.get_g1()) == bytes(pk_list[index])
        signature = AugSchemeMPL.sign(synthetic, msg)
        assert AugSchemeMPL.verify(pk_list[index], msg, signature)
        signatures.append(signature)
    aggsig = AugSchemeMPL.aggregate(signatures)
    assert AugSchemeMPL.aggregate_verify(pk_list, msg_list, aggsig)
    unsigned_tx["aggregated_signature"] = "0x" + bytes(aggsig).hex()
    return unsigned_tx


def create_unsigned_tx(from_pk: str, to_address: str, amount: uint64, fee: int, coins: List):
    to_puzzle_hash = address2_puzzle_hash(to_address)
    transaction = _create_transaction(
        G1Element.from_bytes(hexstr_to_bytes(from_pk)),
        to_puzzle_hash,
        amount,
        fee,
        coins
    )
    msg_list, pk_list = unsigned_coin_solutions(
        transaction,
        bytes.fromhex("ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"),
        11000000000)
    unsigned_tx = {
        "coin_solutions": [t.to_json_dict() for t in transaction],
        "aggregated_signature": "",
    }
    return unsigned_tx, msg_list, pk_list


def _create_transaction(pk: G1Element, to_puzzle_hash: str, amount: uint64, fee: int, coins: List):
    outputs = []
    if not to_puzzle_hash:
        raise ValueError(f"Address is null in send list")
    if amount <= 0:
        raise ValueError(f"Amount must greater than 0")
    to_puzzle_hash = hexstr_to_bytes(to_puzzle_hash)
    total_amount = amount + fee
    outputs.append({"puzzle_hash": to_puzzle_hash, "amount": amount})
    coins = set([Coin.from_json_dict(coin_json) for coin_json in coins])
    spend_value = sum([coin.amount for coin in coins])
    change = spend_value - total_amount
    if change < 0:
        raise ValueError("Insufficient balance")
    transaction: List[CoinSolution] = []
    primary_announcement_hash: Optional[bytes32] = None
    for coin in coins:
        puzzle: Program = puzzle_for_pk(pk)
        if primary_announcement_hash is None:
            primaries = [{"puzzlehash": to_puzzle_hash, "amount": amount}]
            if change > 0:
                change_puzzle_hash: bytes32 = create_puzzlehash_for_pk(pk)
                primaries.append({"puzzlehash": change_puzzle_hash, "amount": change})
            message_list: List[bytes32] = [c.name() for c in coins]
            for primary in primaries:
                message_list.append(Coin(coin.name(), primary["puzzlehash"], primary["amount"]).name())
            message: bytes32 = std_hash(b"".join(message_list))
            solution: Program = make_solution(primaries=primaries, fee=fee, coin_announcements=[message])
            primary_announcement_hash = Announcement(coin.name(), message).name()
        else:
            solution = make_solution(coin_announcements_to_assert=[primary_announcement_hash])
        transaction.append(
            CoinSolution(
                coin,
                SerializedProgram.from_bytes(bytes(puzzle)),
                SerializedProgram.from_bytes(bytes(solution))
            )
        )
    if len(transaction) <= 0:
        raise ValueError("spends is zero")
    return transaction


def make_solution(
        primaries: Optional[List[Dict[str, Any]]] = None,
        min_time=0,
        me=None,
        coin_announcements: Optional[List[bytes32]] = None,
        coin_announcements_to_assert: Optional[List[bytes32]] = None,
        puzzle_announcements=None,
        puzzle_announcements_to_assert=None,
        fee=0,
) -> Program:
    assert fee >= 0
    condition_list = []
    if primaries:
        for primary in primaries:
            condition_list.append(make_create_coin_condition(primary["puzzlehash"], primary["amount"]))
    if min_time > 0:
        condition_list.append(make_assert_absolute_seconds_exceeds_condition(min_time))
    if me:
        condition_list.append(make_assert_my_coin_id_condition(me["id"]))
    if fee:
        condition_list.append(make_reserve_fee_condition(fee))
    if coin_announcements:
        for announcement in coin_announcements:
            condition_list.append(make_create_coin_announcement(announcement))
    if coin_announcements_to_assert:
        for announcement_hash in coin_announcements_to_assert:
            condition_list.append(make_assert_coin_announcement(announcement_hash))
    if puzzle_announcements:
        for announcement in puzzle_announcements:
            condition_list.append(make_create_puzzle_announcement(announcement))
    if puzzle_announcements_to_assert:
        for announcement_hash in puzzle_announcements_to_assert:
            condition_list.append(make_assert_puzzle_announcement(announcement_hash))
    return solution_for_conditions(condition_list)

