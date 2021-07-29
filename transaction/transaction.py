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
    sk = '0x58a8b3237c9981ff476a897fc0d6b377bd5b2e57cbfcdf664c76963a52041012'  # 私钥
    from_pk = '0xb00d72059e10b375275688497476e188066eebfaf7f226daa80cf7a7ad1d4f7ab298a161c453390903a790b11e747789'  # 转出者的公钥
    to_address = 'xch18yjkkst8g0r77d4a664jat223v3mfnytp0r9zsqt9mz2jxdjh7lq9guqra'
    amount = uint64(10)   # 转账金额
    fee = uint64(1)   # 转账手续费
    coins = [{
        'amount': 80,
        'parent_coin_info': '0xb5d31c65960840ea826be97ef7dae140a680a047d48434475eef8bd9062b63e8',
        'puzzle_hash': '0x2c68ed218bd3dc011237a1b79c2669905f763dc3f1ed4fea6ddb1760d12edb78'
    }]   # 类似 input
    tx = Transaction(
        sk=sk,
        from_pk=from_pk,
        to_address=to_address,
        amount=amount,
        fee=fee,
        coins=coins
    )
    print(tx.create_sign_transaction())