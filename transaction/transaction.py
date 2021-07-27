# coding:utf-8

import sys
import json
from typing import List, Dict, Optional, Any
from tx import create_unsigned_tx, sign_tx, create_signed_tx
from base.util.ints import uint64


class Transaction:
    sk: str
    from_pk: str
    to_address: str
    amount: uint64
    fee: uint64
    coins: List

    def __init__(self, sk: str, from_pk: str, to_address: str, amount: uint64, fee: uint64, coins: List):
        self.sk = sk
        self.from_pk = from_pk
        self.to_address = to_address
        self.amount = amount
        self.fee = fee
        self.coins = coins

    def create_sign_transaction(self):
        unsigned_tx, msg_list, pk_list = create_unsigned_tx(
            from_pk=self.from_pk,
            to_address=self.to_address,
            amount=self.amount,
            fee=self.fee,
            coins=self.coins
        )
        return sign_tx(
            sk=self.sk,
            unsigned_tx=unsigned_tx,
            msg_list=msg_list,
            pk_list=pk_list
        )


if __name__ == "__main__":
    tx = Transaction(
        sk=sys.argv[1],
        from_pk=sys.argv[2],
        to_address=sys.argv[3],
        amount=uint64(int(sys.argv[4]),
        fee=uint64(int(sys.argv[5])),
        coins=json.loads(sys.argv[6]))
    print(tx.create_sign_transaction())