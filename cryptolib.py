#!/usr/bin/env python3

from typing import List, Tuple
from collections import defaultdict
from random import shuffle, sample
from hashlib import sha256
from fastecdsa import keys
from fastecdsa.curve import P256 as curve
from fastecdsa.point import Point


def hash_to_int(point: 'Point') -> int:
    return int(sha256(str(point.x) + str(point.y)).hexdigest(), 16)

def hash_to_point(point: 'Point') -> 'Point':
    return curve.G * hash_to_int(point)

def gen_P(r: int, public_key: 'PublicKey') -> 'Point':
    return hash_to_int(r * public_key.A) * curve.G + public_key.B

def gen_p(R: int, private_key: 'PrivateKey') -> int:
    return hash_to_int(private_key.a * R) + private_key.b


class PublicKey:
    """Public key class.

    Attributes:
        A, B (Point): points on curve
    """

    def __init__(self, A: 'Point', B: 'Point'):
        self.A = A
        self.B = B


class PrivateKey:
    """Private key class.

    Attributes:
        a, b (int)
    """

    def __init__(self, a: int, b: int):
        self.a = a
        self.b = b

    def gen_public_key(self) -> 'PublicKey':
        return PublicKey(self.a * curve.G, self.b * curve.G)

    @staticmethod
    def create() -> 'PrivateKey':
        a = keys.gen_private_key(curve)
        b = keys.gen_private_key(curve)
        return PrivateKey(a, b)

    def __str__(self):
        return "(" + format(self.a, '02x') + ", " + format(self.b, '02x') + ")"


class User:
    """User class.
    Attributes:
        private_key (PrivateKey)
    """

    def __init__(self, private_key: 'PrivateKey'):
        self.private_key = private_key

    def gen_public_key(self) -> 'PublicKey':
        return self.private_key.gen_public_key()

    @staticmethod
    def create() -> 'User':
        # TODO: save user into file
        return User(PrivateKey.create())

    # TODO: create load function


class Ring:
    """List of transaction outputs.

    Attributes:
        txos (List[TXO]): list of TXO with same *amount*
    """
    RING_SIZE = 10

    def __init__(self, txos: 'List[TXO]'):
        self.txos = txos

    @staticmethod
    def create(txo: 'TXO', max_size: int = None) -> 'Ring':
        if not max_size:
            max_size = Ring.RING_SIZE
        amount = txo.amount

        txos = txopool.get_sample_list(amount, max_size)
        if txo not in txos:
            txos.pop()
            txos.append(txo)

        shuffle(txos)
        return Ring(txos)


# TODO: Create SignaturePool
# TODO: Create Signature
# TODO: Create verify signature
class Signature:
    """Signature class for Ring-Signature.

    Holds an image, a ring and the constants.
    The Signature signs a ring and is verifies that the TXO
    must be one of the TXOs from the ring (but not which
    one it is).

    Attributes:
        image (Point): TXO unique identifier
        c, r (int): Ring signature constants
        ring (Ring): Ring used for anonymity
    """

    def __init__(self, image: 'Point', c: int, r: int, ring: 'Ring'):
        self.image = image
        self.c = c
        self.r = r
        self.ring = ring

    @staticmethod
    def create(private_key: 'PrivateKey', utxo: 'TXO', ring: 'Ring') -> 'Signature':
        # TODO: create signature
        # TODO: check if txo is unspent (UTXO)
        return Signature(1, 1, 1, 1)


class TXO:
    """Transaction Output class.

    Attributes:
        P (Point): public transaction output address.
        amount (int): transaction output amount (the value of the TXO)
    """

    def __init__(self, P: 'Point', amount: int):
        self.P = P
        self.amount = amount


class TXOPool:
    """Transaction Output pool.
    Holds all TXOs, split by *amount*.

    Attributes:
        pool (Dict[List[TXO]])
    """

    def __init__(self):
        self.pool = defaultdict(set)

    def get_sample_list(self, amount: int, max_size: int) -> 'List[TXO]':
        sample_size = min(max_size, len(self.pool[amount]))
        return sample(self.pool[amount], sample_size)

    def add(self, txo: 'TXO'):
        self.pool[txo.amount].add(txo)


txopool = TXOPool()


class Transaction:
    """Transaction class.

    Attributes:
        R (Point): transaction unique identifier
        inputs (List[Signature]): Signatures of possible TXO used on transaction
        outputs (List[TXO]): TXOs created on transaction
    """

    def __init__(self, R: 'Point', inputs: 'List[Signature]', outputs: 'List[TXO]'):
        self.R = R
        self.inputs = inputs
        self.outputs = outputs

    def __eq__(self, other):
        return self.R == other.R

    # TODO: Create genesis transaction

    @staticmethod
    def create(r: int,
               sender: 'User',
               receiver_amounts: 'List[Tuple[PublicKey, int]]',
               utxos: 'List[TXO]') -> 'Transaction':
        R = r * curve.G
        inputs = []
        outputs = []

        txo_sum = 0
        txi_sum = 0

        for receiver, amount in receiver_amounts:
            P = gen_P(r, receiver)
            outputs.append(TXO(P, amount))
            txo_sum += amount

        for utxo in utxos:
            ring = Ring.create(utxo)
            p = gen_p(utxo.transaction.R, sender.private_key)
            signature = Signature.create(p, utxo, ring)
            inputs.append(signature)

            txi_sum += utxo.amount

        if txo_sum > txi_sum:
            raise Error("Transaction input not sufficient")

        if txi_sum > txo_sum:
            receiver = sender.gen_public_key()
            P = gen_P(r, receiver)
            outputs.append(TXO(P, txi_sum - txo_sum))

        transaction = Transaction(R, inputs, outputs)
        # TODO: Send transaction to TransactionPool
        # TODO: Send signatures to SignaturePool

        return transaction


# TODO: Test flow
# TODO: Create API
# TODO: Create graphical stuff?

