from collections import defaultdict
from random import getrandbits
from cryptolib import *


user = None


def getrand():
    bit_len = curve.q.bit_length()
    return getrandbits(bit_len) % curve.q


def login(username: str, password: str):
    import hashlib
    hash_password = hashlib.sha1(password.encode('utf-8')).hexdigest()

    dbuser = db["Users"].find_one({'user': username, 'password': hash_password})
    if dbuser is not None:
        global user
        user = User.deserialize(dbuser['data'])
        print("Login successful.")
    else:
        print("Login failed.")


def create_user(username: str, password: str):
    import hashlib
    hash_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    db["Users"].insert_one({
        'user': username,
        'password': hash_password,
        'data': User.create().serialize()
    })
    login(username, password)


def require_login(func):
    def func_wrapper(*args, **kwargs):
        if not user or not user.private_key:
            print("User not logged in.")
        else:
            return func(*args, **kwargs)
    return func_wrapper


@require_login
def create_asset(asset_uid: int, amount: int):
    try:
        r = getrand()
        transaction = Transaction.create_genesis(r, user, asset_uid, amount)
        db["LocalTransactions"].insert_one({
            'r': str(r),
            'R': transaction.R.serialize()
        })
        print("Asset created.")
    except ValueError as err:
        print("Error while creating asset:", err)


@require_login
def get_unspent_assets():
    txos = txo_pool.get_list()
    images = image_pool.get_list()

    def test(txo):
        p = get_p(txo.R, user.private_key)
        return (get_point(p) == txo.P and
                get_image(p) not in images)

    utxos = list(filter(test, txos))
    return utxos


@require_login
def list_assets():
    utxos = get_unspent_assets()

    assets = defaultdict(int)
    for txo in utxos:
        assets[txo.T] += txo.amount

    if len(assets) == 0:
        print("No assets!")
    else:
        for T, amount in assets.items():
            print("Asset " + str(T) + ": " + str(amount))


@require_login
def get_excerpt():
    pass


@require_login
def make_transaction(asset_uid: int, receiver_amounts: 'Dict[PublicKey, int]'):
    assets = list(filter(lambda txo: txo.T == asset_uid, get_unspent_assets()))

    desired_amount = sum(receiver_amounts.values())

    if sum(map(lambda txo : txo.amount, assets)) < desired_amount:
        print("Not enough to transfer.")
        return

    utxos = []
    amount = 0
    for utxo in assets:
        if amount >= desired_amount:
            break
        utxos.append(utxo)
        amount += utxo.amount

    try:
        r = getrand()
        transaction = Transaction.create(r, user, receiver_amounts, utxos)
        db["LocalTransactions"].insert_one({
            'r': str(r),
            'R': transaction.R.serialize()
        })
        print("Transfer successful.")
    except ValueError as err:
        print("Error while creating asset:", err)


@require_login
def generate_asset_receipt(asset: 'TXO'):
    G = curve.G

    R = asset.R
    db_asset = db["LocalTransactions"].find_one({ 'R': R.serialize() })

    if db_asset is None:
        print("Not owner of transaction!")
        return

    r = int(db_asset['r'])

    k = getrand()
    A = asset.public_key.A

    c = hash_point_list([r*A, k*A, k*G])
    s = (k + c*r) % curve.q

    return [R, A, s, r*A, k*A, k*G]


@require_login
def verify_asset_receipt(receipt):
    G = curve.G
    R, A, s, rA, kA, kG = receipt
    c = hash_point_list([rA, kA, kG])

    # TODO: check if asset is the same as requested!

    return (s*G == kG + c*R and s*A == kA + c*rA)


@require_login
def generate_ownership_receipt(asset: 'TXO'):
    G = curve.G

    P = asset.P
    p = get_p(asset.R, user.private_key)

    if get_point(p) != P:
        print("Not owner of asset!")
        return None

    k = getrand()
    HP = hash_to_point(P)
    I = p * HP

    c = hash_point_list([I, k * HP, k*G])
    s = (k + c*p) % curve.q

    return [P, s, I, k * HP, k*G]


@require_login
def verify_ownership_receipt(receipt):
    G = curve.G
    P, s, I, kHP, kG = receipt
    HP = hash_to_point(P)
    c = hash_point_list([I, kHP, kG])

    # TODO: check if asset is the same as requested!

    if db["ImagePool"].find_one(I.serialize()) is not None:
        return False

    return (s*G == kG + c*P and s*HP == kHP + c*I)
