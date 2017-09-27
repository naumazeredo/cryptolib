#!/usr/bin/env python3

from cryptolib import *

client.drop_database("test-PFCDB")
db = client["test-PFCDB"]

image_pool.pool = db["ImagePool"]
txo_pool = db["TXOPool"]
transaction_pool = db["TransactionPool"]

G = curve.G

g_dic = {
    'x' : '48439561293906451759052585252797914202762949526041747995844080717082404635286',
    'y' : '36134250956749795798585127919587881956611106672985015071877198253568414405109'}

sk_dic = {
    'a': '78249293113199110214323280884516338625390727449696738378581013760886194308870',
    'b': '73536829615446284129359712566833812177286578192089963943467768797891589628045'}

pk_dic = {
    'A': (78249293113199110214323280884516338625390727449696738378581013760886194308870 * G).serialize(),
    'B': (73536829615446284129359712566833812177286578192089963943467768797891589628045 * G).serialize()}

sk = PrivateKey(int(sk_dic['a']), int(sk_dic['b']))
pk = sk.get_public_key()

usr = User(sk)
rcv = User.create().get_public_key()

r1 = 85814027921026973543539706148396817123224058635847751659597460573099266630554
r2 = 48959747610750136911948260825163278570854261766721583707069542526088554036864
r3 = 104852587341113109515259000720869421723774691523880821868257127866318165634805

P1 = get_P(r1, pk)
p1 = get_p(r1*G, sk)

P2 = get_P(r2, pk)
p2 = get_p(r2*G, sk)

P3 = get_P(r3, pk)
p3 = get_p(r3*G, sk)

txos = [TXO(P1, 10), TXO(P2, 10), TXO(P3, 10)]
serialized_txos = [TXO(P1, 10).serialize(), TXO(P2, 10).serialize(), TXO(P3, 10).serialize()]
txo = txos[0]

ring = Ring(txos)
signature = Signature.create(p1, txo, ring)

img = p1*hash_to_point(P1)
cs = [str(c) for c in signature.cs]
rs = [str(r) for r in signature.rs]
r_dic = ring.serialize()

rg1 = 105302519521812717116318027275652627657554197927473744794739667748946304901374
rg2 = 62747684084566402829733256825691886459511814419445930382914517906404482991334

gen1 = Transaction.create_genesis(rg1, usr, 10)
gen2 = Transaction.create_genesis(rg2, usr, 10)


rt = 62000755505829664278669978347292861349108377683113101656333622619248103434192
tran = Transaction.create(rt, usr, {rcv : 10}, gen1.outputs + gen2.outputs)

t_dic = {
        'R' : (rt*G).serialize(),
        'inputs' : [txo.serialize() for txo in tran.inputs],
        'outputs' : [txo.serialize() for txo in tran.outputs]}

def test_serialize_Point():
    dic = curve.G.serialize()
    assert dic == g_dic

def test_deserialize_Point():
    assert curve.G == Point.deserialize(g_dic)

def test_serialize_PrivateKey():
    assert sk.serialize() == sk_dic

def test_deserialize_PrivateKey():
    assert sk == PrivateKey.deserialize(sk_dic)

def test_serialize_PublicKey():
    assert pk.serialize() == pk_dic

def test_deserialize_PublicKey():
    assert pk == PublicKey.deserialize(pk_dic)

def test_serialize_User():
    assert usr.serialize() == {'private_key' : sk_dic}

def test_deserialize_User():
    assert usr == User.deserialize({'private_key' : sk_dic})

def test_serialize_TXO():
    assert txo.serialize() == {'P' : P1.serialize(), 'amount' : '10'}

def test_deserialize_TXO():
    assert txo == TXO.deserialize({'P' : P1.serialize(), 'amount' : '10'})

def test_serialize_Ring():
    assert ring.serialize() == {'txos' : serialized_txos}

def test_deserialize_Ring():
    assert ring == Ring.deserialize({'txos' : serialized_txos})

def test_serialize_Signature():
    assert signature.serialize() == {'image' : img.serialize(), 'cs' : cs, 'rs' : rs, 'ring' : r_dic}

def test_deserialize_Signature():
    assert signature == Signature.deserialize({'image' : img.serialize(), 'cs' : cs, 'rs' : rs, 'ring' :r_dic})

def test_serialize_Transaction():
    assert tran.serialize() == t_dic

def test_deserialize_Transaction():
    assert tran == Transaction.deserialize(t_dic)
