#!/usr/bin/env python3

from typing import List, Tuple
from collections import defaultdict
from random import shuffle, sample, getrandbits
from hashlib import sha256
from fastecdsa import keys
from fastecdsa.curve import P256 as curve
from fastecdsa.point import Point


def point_to_str(point: 'Point') -> str:
    return (str(point.x) + str(point.y))

def hash_to_int(point: 'Point') -> int:
    return int(sha256(point_to_str(point).encode('utf-8')).hexdigest(), 16)

def hash_to_point(point: 'Point') -> 'Point':
    return curve.G * hash_to_int(point)

def hash_signature(ls: 'List[Point]', rs: 'List[Point]'):
    s = ""
    for p in ls: s += point_to_str(p)
    for p in rs: s += point_to_str(p)
    s = s.encode('utf-8')
    return int(sha256(s).hexdigest(), 16)

def gen_P(r: int, public_key: 'PublicKey') -> 'Point':
    return hash_to_int(r * public_key.A) * curve.G + public_key.B

def gen_p(R: 'Point', private_key: 'PrivateKey') -> int:
    return hash_to_int(R * private_key.a) + private_key.b


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
class Signature:
    """Signature class for Ring-Signature.

    Holds an image, a ring and the constants.
    The Signature signs a ring and is verifies that the TXO
    must be one of the TXOs from the ring (but not which
    one it is).

    Attributes:
        image (Point): TXO unique identifier
        c, r (List[int]): Ring signature constants
        ring (Ring): Ring used for anonymity
    """

    def __init__(self, image: 'Point', cs: 'List[int]', rs: 'List[int]', ring: 'Ring'):
        self.image = image
        self.cs = cs
        self.rs = rs
        self.ring = ring

    @staticmethod
    def create(private_key: 'PrivateKey', utxo: 'TXO', ring: 'Ring') -> 'Signature':
        if utxo not in ring.txos:
            return None

        index = ring.txos.index(utxo)
        qnt = len(ring.txos)

        P = private_key * curve.G
        I = private_key * hash_to_point(P)

        qs = [getrandbits(128) for i in range(qnt)]
        ws = [getrandbits(128) for i in range(qnt)]

        Ls = [(qs[i] * curve.G if i == index else qs[i] * curve.G + ws[i] * ring.txos[i].P) for i in range(qnt)]
        Rs = [(qs[i] * hash_to_point(ring.txos[i].P) if i == index else qs[i] * hash_to_point(ring.txos[i].P) + ws[i] * I) for i in range(qnt)]
        c = hash_signature(Ls, Rs)

        print("L R")
        for l in Ls: print(l)
        for r in Rs: print(r)

        print(c)

        sum_ws = sum(ws) - ws[ring.txos.index(utxo)]

        cs = [(c - sum_ws if i == index else ws[i]) for i in range(qnt)]
        rs = [(qs[i] - cs[i] * private_key if i == index else qs[i]) for i in range(qnt)]

        for c in cs: print(c)

        return Signature(I, cs, rs, ring)

    def not_used(self) -> bool:
        # Verify if image was not used
        if image_pool.get(self.image) is not None:
            return False
        print("OK")

        # Verify if the signature is correct
        qnt = len(self.ring.txos)
        Ls = [self.rs[i] * curve.G + self.cs[i] * self.ring.txos[i].P for i in range(qnt)]
        Rs = [self.rs[i] * hash_to_point(self.ring.txos[i].P) + self.cs[i] * self.image for i in range(qnt)]
        print("L R")
        for l in Ls: print(l)
        for r in Rs: print(r)
        print(hash_signature(Ls, Rs))

        return sum(self.cs) == hash_signature(Ls, Rs)


class SignatureImagePool:
    """Signature Image pool.

    Attributes:
        pool (Dict[int, Signature])
    """

    def __init__(self):
        self.pool = {}

    def add(self, signature: 'Signature'):
        self.pool[hash_to_int(signature.image)] = signature

    def get(self, image: 'Point'):
        return self.pool.get(hash_to_int(image))


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
        pool (Dict[int, List[TXO]])
    """

    def __init__(self):
        self.pool = defaultdict(set)

    def get_sample_list(self, amount: int, max_size: int) -> 'List[TXO]':
        sample_size = min(max_size, len(self.pool[amount]))
        return sample(self.pool[amount], sample_size)

    def add(self, txo: 'TXO'):
        self.pool[txo.amount].add(txo)


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

    @staticmethod
    def create_genesis(r: int, creator: 'User', amount: int):
        R = r * curve.G
        P = gen_P(r, creator.gen_public_key())

        utxo = TXO(P, amount)
        transaction = Transaction(R, [], [utxo])
        transaction_pool.add(transaction)

        return transaction

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

            if not signature:
                raise Error("Signature not valid.")

            inputs.append(signature)

            txi_sum += utxo.amount

        if txo_sum > txi_sum:
            raise Error("Transaction input not sufficient.")

        if txi_sum > txo_sum:
            receiver = sender.gen_public_key()
            P = gen_P(r, receiver)
            outputs.append(TXO(P, txi_sum - txo_sum))

        transaction = Transaction(R, inputs, outputs)
        transaction_pool.add(transaction)

        return transaction


class TransactionPool:
    """Transaction pool.

    Attributes:
        pool (List[Transaction])
    """

    def __init__(self):
        self.pool = []

    def add(self, transaction: 'Transaction'):
        # TODO: Verify signatures
        # TODO: Verify if transaction is possible (utxos by sender: signature?)
        # TODO: Send signatures to SignaturePool

        for utxo in transaction.outputs:
            utxo.transaction = transaction
            txo_pool.add(utxo)

        self.pool.append(transaction)


image_pool = SignatureImagePool()
txo_pool = TXOPool()
transaction_pool = TransactionPool()

# TODO: Use mongodb instead of (some) pools (persistent: transactions, txos and signatures. generated: images and txo_by_amount)
# TODO: Create API
# TODO: Create graphical stuff?

