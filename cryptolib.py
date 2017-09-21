#!/usr/bin/python

from random import shuffle, sample
from hashlib import sha256
from fastecdsa import keys
from fastecdsa.curve import P256 as curve
from fastecdsa.point import Point

# TODO: util class
def hash_to_int(point):
    return int(sha256(str(point.x) + str(point.y)).hexdigest(), 16)

def hash_to_point(point):
    return curve.G * hash_to_int(point)

def gen_P(r, public_key):
    return hash_to_int(r * public_key.A) * curve.G + public_key.B

def gen_p(R, private_key):
    return hash_to_int(private_key.a * R) + private_key.b


class PrivateKey:
    def __init__(self):
        self.a = keys.gen_private_key(curve)
        self.b = keys.gen_private_key(curve)

    def gen_public_key(self):
        return PublicKey(self.a * curve.G, self.b * curve.G)


class PublicKey:
    def __init__(self, A, B):
        self.A = A
        self.B = B


class User:
    def __init__(self, private_key):
        self.private_key = private_key

    def gen_public_key(self):
        return private_key.gen_public_key()


class Ring:
    RING_SIZE = 10

    def __init__(self, txo):
        self.txos = txos

    def create(txo, max_size = self.RING_SIZE):
        amount = txo.amount

        txos = TXOPool.get_txo(amount, max_size)
        if txo not in txos:
            txos.pop()
            txos += txo

        shuffle(txos)
        return Ring(txos)


# TODO: Create Signature
class Signature:
    def __init__(self, image, c, r, ring):
        self.image = image
        self.c = c
        self.r = r
        self.ring = ring

    def create(private_key, utxo, ring):
        # TODO: create signature
        return Signature(1, 1, 1, 1)

class TXOPool:
    """ Singleton class that stores all transactions """
    class Pool:
        def __init__(self):
            self.pool = {}

        def get_txo(amount, max_size):
            sample_size = min(max_size, len(self.pool[amount]))
            return random.sample(self.pool[amount], sample_size)

    instance = None
    def __init__(self):
        if not TXOPool.instance:
            TXOPool.instance = TXOPool.Pool()

    def __getattr__(self, name):
        return getattr(self.instance, name)


class Transaction:
    def __init__(self, R, inputs, outputs):
        self.R = R
        self.inputs = inputs
        self.outputs = outputs

    def __eq__(self, other):
        return self.R == other.R

    def create(r, sender, receiver_amounts, utxos):
        R = r * curve.G
        inputs = []
        outputs = []

        txo_sum = 0
        txi_sum = 0

        for receiver, amount in receiver_amounts:
            P = gen_P(r, receiver)
            outputs += TXO(P, amount)
            txo_sum += amount

        for utxo in utxos:
            ring = Ring.create(utxo)
            p = gen_p(utxo.transaction.R, sender.private_key)
            signature = Signature.create(p, utxo, ring)
            inputs += signature

            txi_sum += utxo.amount

        if txo_sum > txi_sum:
            raise Error("Transaction input not sufficient")

        if txi_sum > txo_sum:
            receiver = sender.gen_public_key()
            P = gen_P(r, receiver)
            outputs += TXO(P, txi_sum - txo_sum)

        return Transaction(R, inputs, outputs)

