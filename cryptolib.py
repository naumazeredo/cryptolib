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


class Ring:
    RING_SIZE = 10

    def __init__(self, transactions):
        self.transactions = transactions

    def create(transaction, max_size = self.RING_SIZE):
        amount = transaction.amount

        transactions = TransactionPool.get_transactions_by_amount(amount, max_size)
        if transaction not in transactions:
            transactions.pop()
            transactions += transaction

        shuffle(transactions)
        return Ring(transactions)


# TODO: Create Signature

class TransactionPool:
    """ Singleton class that stores all transactions """
    class Pool:
        def __init__(self):
            self.pool = {}

        def get_transactions_by_amount(amount, max_size):
            sample_size = min(max_size, len(self.pool[amount]))
            return random.sample(self.pool[amount], sample_size)

    instance = None
    def __init__(self):
        if not TransactionPool.instance:
            TransactionPool.instance = TransactionPool.Pool()

    def __getattr__(self, name):
        return getattr(self.instance, name)


class Transaction:
    def __init__(self, R, P, amount, signatures):
        self.R = R
        self.P = P
        self.amount = amount
        self.signatures = signatures

    def create(r, amount, sender, receiver_pub, transactions):
        R = r * curve.G
        P = gen_P(r, receiver_pub)
        p = gen_p(R, sender.private_key)
        signatures = []

        for transaction in transactions:
            ring = Ring.create(transaction)
            signature = Signature.create(p, transaction, ring)
            signatures += signature

        transaction = Transaction(R, P, amount, signatures)
        # TODO: verify stuff and add to TransactionPool
        # TODO: solve change problem!!!

        return transaction

    # TODO: define == operator

