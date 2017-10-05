#!/usr/bin/env python3

from collections import defaultdict
from random import shuffle, sample, getrandbits
from hashlib import sha256
from fastecdsa import keys
from fastecdsa.curve import P256 as curve
from fastecdsa.point import Point
from pymongo import MongoClient
client = MongoClient()
db = client["PFCDB"]

# Serialization capacities to Point class
def __serialize_point(self):
    return {'x' : str(self.x), 'y' : str(self.y)}

def __deserialize_point(dic : dict):
    return Point(int(dic["x"]), int(dic["y"]), curve)

setattr(Point, 'serialize', __serialize_point)
setattr(Point, 'deserialize', staticmethod(__deserialize_point))

# Auxiliary hash functions
def point_to_str(point: 'Point') -> str:
    return (str(point.x) + str(point.y))

def hash_to_int(point: 'Point') -> int:
    return int(sha256(point_to_str(point).encode('utf-8')).hexdigest(), 16)

def hash_to_point(point: 'Point') -> 'Point':
    return curve.G * hash_to_int(point)

def hash_point_list(l: 'List[Point]'):
    s = ""
    for p in l: s += point_to_str(p)
    s = s.encode('utf-8')
    return int(sha256(s).hexdigest(), 16) % curve.q

def get_P(r: int, public_key: 'PublicKey') -> 'Point':
    return hash_to_int(r * public_key.A) * curve.G + public_key.B

def get_p(R: 'Point', private_key: 'PrivateKey') -> int:
    return hash_to_int(R * private_key.a) + private_key.b

def get_image(p: int):
    return p * hash_to_point(p * curve.G)

def get_point(x: int):
    return x * curve.G


class PublicKey:
    """Public key class.

    Attributes:
        A, B (Point): points on curve
    """

    def __init__(self, A: 'Point', B: 'Point'):
        self.A = A
        self.B = B

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __hash__(self):
        return hash_to_int(self.A) * hash_to_int(self.B) % curve.q

    def serialize(self) -> dict:
        A = self.A.serialize()
        B = self.B.serialize()
        return {'A' : A, 'B' : B}

    @staticmethod
    def deserialize(dic : dict) -> 'PublicKey':
        A = Point.deserialize(dic['A'])
        B = Point.deserialize(dic['B'])
        return PublicKey(A, B)

class PrivateKey:
    """Private key class.

    Attributes:
        a, b (int)
    """

    def __init__(self, a: int, b: int):
        self.a = a
        self.b = b

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def get_public_key(self) -> 'PublicKey':
        return PublicKey(self.a * curve.G, self.b * curve.G)

    def serialize(self) -> dict:
        return {'a' : str(self.a), 'b' : str(self.b)}

    @staticmethod
    def deserialize(dic : dict) -> 'PrivateKey':
        return PrivateKey(int(dic['a']), int(dic['b']))

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

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    @staticmethod
    def create() -> 'User':
        return User(PrivateKey.create())

    @staticmethod
    def deserialize(dic : dict) -> 'User':
        private_key = PrivateKey.deserialize(dic["private_key"])
        return User(private_key)

    def serialize(self) -> dict:
        return {'private_key' : self.private_key.serialize()}

    def get_public_key(self) -> 'PublicKey':
        return self.private_key.get_public_key()


class TXO:
    """Transaction Output class.

    Attributes:
        P (Point): public transaction output address.
        amount (int): transaction output amount (the value of the TXO)
    """

    def __init__(self, P: 'Point', amount: int, public_key: 'PublicKey' = None, R: 'Point' = None):
        self.P = P
        self.amount = amount
        self.R = R
        self.public_key = public_key

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.serialize() == other.serialize()

    def __hash__(self):
        return hash_to_int(self.P)

    @staticmethod
    def deserialize(dic : dict) -> 'TXO':
        P = Point.deserialize(dic['P'])
        amount = int(dic['amount'])
        public_key = PublicKey.deserialize(dic['public_key'])

        R = dic.get('R')
        if R is not None:
            R = Point.deserialize(R)
        return TXO(P, amount, public_key, R)

    def serialize(self) -> dict:
        dic = {
            'P' : self.P.serialize(),
            'amount' : str(self.amount),
            'public_key' : self.public_key.serialize()
        }
        if self.R is not None:
            dic['R'] = self.R.serialize()
        return dic




class Ring:
    """List of transaction outputs with same amount.

    Attributes:
        txos (List[TXO]): list of TXO with same *amount*
    """
    RING_SIZE = 10

    def __init__(self, txos: 'List[TXO]'):
        self.txos = txos

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    @staticmethod
    def create(txo: 'TXO', max_size: int = None) -> 'Ring':
        if not max_size:
            max_size = Ring.RING_SIZE
        amount = txo.amount

        txos = txo_pool.get_sample_list(amount, max_size)
        if txo not in txos:
            if len(txos) == max_size:
                txos.pop()
            txos.append(txo)

        shuffle(txos)
        return Ring(txos)

    @staticmethod
    def deserialize(dic : dict) -> 'Ring':
        return Ring([TXO.deserialize(txo) for txo in dic['txos']])

    def serialize(self) -> dict:
        return {'txos' : [txo.serialize() for txo in self.txos]}


class Signature:
    """Signature class for Ring-Signature.

    Holds an image, a ring and the constants.
    The Signature signs a ring and is verifies that the TXO
    must be one of the TXOs from the ring (but not which
    one it is).

    Attributes:
        image (Point): TXO unique identifier
        cs, rs (List[int]): Ring signature constants
        ring (Ring): Ring used for anonymity
    """

    def __init__(self, image: 'Point', cs: 'List[int]', rs: 'List[int]', ring: 'Ring'):
        self.image = image
        self.cs = cs
        self.rs = rs
        self.ring = ring

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    @staticmethod
    def create(p: int, utxo: 'TXO', ring: 'Ring') -> 'Signature':
        if utxo not in ring.txos:
            return None

        index = ring.txos.index(utxo)
        qnt = len(ring.txos)

        P = p * curve.G
        I = p * hash_to_point(P)

        bit_len = curve.q.bit_length()

        qs = [getrandbits(bit_len) % curve.q for i in range(qnt)]
        ws = [getrandbits(bit_len) % curve.q for i in range(qnt)]

        Ls = [(qs[i] * curve.G if i == index else qs[i] * curve.G + ws[i] * ring.txos[i].P) for i in range(qnt)]
        Rs = [(qs[i] * hash_to_point(P) if i == index else qs[i] * hash_to_point(ring.txos[i].P) + ws[i] * I) for i in range(qnt)]
        c = hash_point_list(Ls + Rs)


        ci = (c - sum(ws) + ws[index]) % curve.q
        cs = [(ci if i == index else ws[i]) for i in range(qnt)]

        qi = (qs[index] - cs[index] * p) % curve.q
        rs = [(qi if i == index else qs[i]) for i in range(qnt)]

        return Signature(I, cs, rs, ring)

    @staticmethod
    def deserialize(dic : dict) -> 'Signature':
        image = Point.deserialize(dic["image"])
        cs = [int(c) for c in dic['cs']]
        rs = [int(r) for r in dic['rs']]
        ring = Ring.deserialize(dic["ring"])
        return Signature(image, cs, rs, ring)

    def serialize(self) -> dict:
        image = self.image.serialize()
        cs = [str(c) for c in self.cs]
        rs = [str(r) for r in self.rs]
        ring = self.ring.serialize()
        return {'image' : image, 'cs' : cs, 'rs' : rs, 'ring' : ring}

    def validate(self) -> bool:
        # Verify if image was not used
        if image_pool.contains(self.image):
            return False

        # Verify if the signature is correct
        qnt = len(self.ring.txos)
        Ls = [self.rs[i] * curve.G + self.cs[i] * self.ring.txos[i].P for i in range(qnt)]
        Rs = [self.rs[i] * hash_to_point(self.ring.txos[i].P) + self.cs[i] * self.image for i in range(qnt)]

        return sum(self.cs) % curve.q == hash_point_list(Ls + Rs)


class SignatureImagePool:
    """Signature Image pool.

    Attributes:
        pool (Dict[int, Signature])
    """

    def __init__(self):
        self.pool = db["ImagePool"]

    def add(self, signature: 'Signature'):
        self.pool.insert_one(signature.image.serialize())

    def contains(self, image: 'Point') -> bool:
        return self.pool.find_one(image.serialize()) is not None

    def get_list(self):
        images = list(self.pool.find())
        return [Point.deserialize(i) for i in images]


class TXOPool:
    """Transaction Output pool.
    Holds all TXOs, split by *amount*.

    Attributes:
        pool (Dict[int, List[TXO]])
    """

    def __init__(self):
        self.pool = db["TXOPool"]

    def get_sample_list(self, amount: int, max_size: int) -> 'List[TXO]':
        ans = self.pool.find({'amount' : amount})
        txos = sample(list(ans), min(max_size, ans.count()))
        return [TXO.deserialize(txo) for txo in txos]

    def get_list(self):
        txos = list(self.pool.find())
        return [TXO.deserialize(txo) for txo in txos]

    def add(self, txo: 'TXO'):
        self.pool.insert_one(txo.serialize())


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
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    @staticmethod
    def create_genesis(r: int, creator: 'User', amount: int):
        R = r * curve.G
        P = get_P(r, creator.get_public_key())

        utxo = TXO(P, amount, creator.get_public_key())
        transaction = Transaction(R, [], [utxo])
        transaction_pool.add(transaction)

        return transaction

    @staticmethod
    def create(r: int,
               sender: 'User',
               receiver_amounts: 'Dict[PublicKey, int]',
               utxos: 'List[TXO]') -> 'Transaction':
        R = r * curve.G
        inputs = []
        outputs = []

        txo_sum = 0
        txi_sum = 0

        for receiver, amount in receiver_amounts.items():
            P = get_P(r, receiver)
            outputs.append(TXO(P, amount, receiver))
            txo_sum += amount

        for utxo in utxos:
            ring = Ring.create(utxo)
            p = get_p(utxo.R, sender.private_key)
            signature = Signature.create(p, utxo, ring)
            if not signature:
                raise ValueError("Signature not valid.")

            inputs.append(signature)
            txi_sum += utxo.amount

        if txo_sum > txi_sum:
            raise ValueError("Transaction input not sufficient.")

        if txi_sum > txo_sum:
            receiver = sender.get_public_key()
            P = get_P(r, receiver)
            outputs.append(TXO(P, txi_sum - txo_sum, sender.get_public_key()))

        transaction = Transaction(R, inputs, outputs)
        transaction_pool.add(transaction)

        return transaction

    @staticmethod
    def deserialize(dic : dict) -> 'Transaction':
        R = Point.deserialize(dic['R'])
        inputs = [Signature.deserialize(signature) for signature in dic['inputs']]
        outputs = [TXO.deserialize(txo) for txo in dic['outputs']]
        return Transaction(R, inputs, outputs)

    def serialize(self) -> dict:
        R = self.R.serialize()
        inputs = [signature.serialize() for signature in self.inputs]
        outputs  = [txo.serialize() for txo in self.outputs]
        return {'R' : R, 'inputs' : inputs, 'outputs' : outputs}


class TransactionPool:
    """Transaction pool.

    Attributes:
        pool (List[Transaction])
    """

    def __init__(self):
        self.pool = db["TransactionPool"]

    def add(self, transaction: 'Transaction', new: bool = False):
        """
        if new and self.pool.find_one({'R': transaction.serialize().R}) is not None:
            raise ValueError
        """

        for signature in transaction.inputs:
            if not signature.validate():
                raise ValueError("Signature not valid.")

        for signature in transaction.inputs:
            image_pool.add(signature)

        for utxo in transaction.outputs:
            utxo.R = transaction.R
            txo_pool.add(utxo)

        self.pool.insert_one(transaction.serialize())

    def get_list(self):
        ts = list(self.pool.find())
        return [Transaction.deserialize(t) for t in ts]

image_pool = SignatureImagePool()
txo_pool = TXOPool()
transaction_pool = TransactionPool()
