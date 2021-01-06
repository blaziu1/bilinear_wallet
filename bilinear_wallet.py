import random
import os
import bn256
import math
from bplib.bp import BpGroup
from bplib.bp import G1Elem
from inspect import getmembers, isfunction
from pyseltongue import SecretSharer
from pyseltongue import secret_int_to_points, points_to_secret_int


class PrivateKeyGenerator:
    def __init__(self):
        print("Instance of Private Key Generator created")

    def generate_groups(self):
        self.G = BpGroup()
        self.q = self.G.order()
        #print("Generated cyclic groups")

    def choose_generator(self):
        self.G1, self.G2 = self.G.gen1(), self.G.gen2()
        #print("Created generators")

    def return_P(self):
        return self.G2

    def select_s(self, q):
        #self.s = random.randint(0, int(q))tak powinno byc
        self.s = random.randint(0, math.floor(math.sqrt(4294967294))) #tak działa bo to max 32-intiger, przemyśleć co z tym zrobić
        print("s: " + str(self.s))
        #print("Selected random s")

    def set_P_pub(self):
        self.P_pub = self.G1.mul(self.s)
        #print("Created P_pub")

    def return_G(self):
        return self.G

    def hash_function_to_group(self, msg):
        return self.G.hashG1(str(msg).encode('utf-8'))

    def hash_function_to_zq(self, msg):
        return hash(msg) % self.q

    def compute_signature(self, id):
        H = self.hash_function_to_group(str(self.P_ver.export()) + "$" + str(id))
        signature = H.mul(self.s)
        #print("PKG calculated a signature")
        return signature

    def compute_P_ver(self, K):
        self.P_ver = self.s * K
        return self.P_ver

    def compute_sQ_id(self, id):
        Q_id = self.hash_function_to_group(id)
        sQ_id = Q_id.mul(self.s)
        #print("sQid was calculated")
        return sQ_id

    def compute_public_parameters(self):
        self.public_parameters = (self.G, self.G1, self.G2, self.q, self.P_pub, self.hash_function_to_group, self.hash_function_to_zq) #self.G2 to P

class PublicBoard:
    def __init__(self):
        print("Public board created")

    def receive_parameters(self, signature, public_parameters, pg_id, m, P_ver, user_id):
        self.signature = signature
        self.public_parameters = public_parameters
        self.pg_user_id = pg_id
        self.m = m
        self.P_ver = P_ver
        self.user_id = user_id

class ProxySigner:
    def __init__(self):
        print("Instance of Proxy Signer created")

class User:
    def __init__(self, id):
        print("Instance of User created with ID: " + str(id))
        self.id = id
        self.Ais = []
        self.Aprim_i_received = []
        self.B_group = []
        self.E = []
        self.signatures = []

    def select_k(self):
        self.k = random.randint(0, math.floor(math.sqrt(4294967294)))
        print("k: " + str(self.k))
        #print("Selected random k")

    def compute_x_i(self):
        self.x_i = random.randint(0, 2147483647)
        print("x_i: " + str(self.x_i))

    def compute_warrant(self, UG):
        self.warrant = []
        self.warrant.append(self.id)
        for u in UG:
            self.warrant.append(u.id)
        self.warrant.append(self.P_ver.export())
        self.warrant.append(self.sig.export())
        #print("Warrant was computed")

    def compute_D_kwt(self, hash):
        self.D_kwt = self.D_proxy.mul(hash)
        #print("D_kwt was calculated")

    def compute_I_kwt(self, t):
        w_to_str = '&'.join([str(elem) for elem in self.warrant])
        self.I_kwt = str(self.k) + "$" + w_to_str + "$" + str(t)
        #print("I_kwt was calculated")

    def compute_commitment(self, P):
        self.K = P.mul(self.k)
        #print("Commitment K was computed")

    def select_x_id(self, q):
        self.x_id = random.randint(0, q)
        print("x_id: " + str(self.x_id))
        #print("Random x_id was calculated")

    def receive_P_ver(self, P_ver):
        self.P_ver = P_ver
        #print("P_ver was received")

    def send_committment(self):
        return self.K

    def compute_D_proxy(self, sQid):
        self.D_proxy = sQid.mul(self.k)
        #print("D_proxy was calculated")

    def receive_pkg_signature(self, sig):
        self.sig = sig
        #print("Signature from PKG was received")

    def shamir_split(self, secret, share_threshold, num_shares, P):
        self.shares, self.coefficients, self.prime = secret_int_to_points(secret, share_threshold, num_shares)
        self.aiP = []
        for c in self.coefficients:
            self.aiP.append(P.mul(c))
        #print("Shamir shares and related committments were calculated")

    def send_aiP(self):
        #print("aiP sent")
        return self.aiP

    def send_share(self, i):
        #print("Sending a share")
        return self.shares[i]

    def verify_share_correctness(self, P, t): #na razie nieużywane
        left = P.mul(self.x_idi[1])
        i = self.x_idi[0]
        right = 0
        for j in range(0, t):
            R = R + (1**i)*coefficients[i] #przemyśleć co z tym zrobić
        R = R % prime

    def shamir_recover(self, shares): #na razie nieużywane
        self.recovered_secret = SecretSharer.points_to_secret_int(shares)

    def receive_share_and_committment(self, x_idi, committment):
        self.x_idi = x_idi
        self.aiP2 = committment #aiP2 ??
        #print("Share and committments were received")

    def compute_A_i(self, m, G):
        msg = str(self.id) + m
        #print("msg: " + msg)
        #print(self.x_idi)
        self.P_m = G.hashG1(msg.encode('utf-8'))
        #print(self.P_m)
        self.A_i = self.P_m.mul(self.x_idi[1])
        #print(self.A_i)
        #print("Ai was calculated")

    def compute_Aprim_i(self, G, m, w, t, UGprim):
        w_to_str = '&'.join([str(elem) for elem in w])
        UGprim_to_str = '&'.join([str(elem) for elem in UGprim])
        M = m + '$' + w_to_str + '$' + str(t) + '$' + UGprim_to_str
        msg = str(self.id) + m
        self.P_M = G.hashG1(msg.encode('utf-8'))
        self.Aprim_i = self.P_M.mul(self.x_i)
        #print("Aprimi calculated")

    def send_Aprim_i(self):
        #print("Sending Aprim_i")
        return self.Aprim_i

    def receive_Aprim_i(self, Aprim_i):
        self.Aprim_i_received.append(Aprim_i)
        #print("Aprim_i received")

    def compute_B(self, P):
        self.B = P.mul(self.x_id)
        #print("Computed B **************************** " + str(self.x_id))

    def compute_C_proxy(self, Q_id, q): # to samo co Ckwt
        self.C_proxy = Q_id.mul(self.x_id) + self.D_proxy.mul(hash(self.I_kwt) % q) # zdefiniowac Ikwt gdzieś
        #print("C_proxy was calculated")

    def compute_E(self, G, M, P): #na razie nieużywane, uzgodnic z Profesorem
        for u in proxy_signers_prim:
            msg = u.id + M
            A = G.hashG1(msg.encode('utf-8'))
            B = u.B
            C_proxy = u.C_proxy
            sigma = [A, B, C_proxy]
            sigma_to_str = '&'.join([str(elem) for elem in sigma])
            msg2 = sigma_to_str + '$' + u.id
            H = G.hashG1(msg2.encode('utf-8'))
            E.append(H.mul(self.xi))

    def compute_A_pg(self, x_id):
        #print("################" + str(x_id))
        self.A = self.P_m.mul(x_id)

    def receive_B(self, B):
        self.B = B
        
    def compute_B_i(self, P):
        self.B_i = P.mul(self.x_i)
        #print("B_i calculated")

    def send_B_i(self):
        #print("Sending B_i")
        return self.B_i

    def receive_B_i(self, B_i):
        self.B_group.append(B_i)
        #print("B_i received")

    def compute_complete_signature(self):
        E = [self.Aprim_i] + self.Aprim_i_received
        #print("Returning complete signature")
        #print(self.A_i)
        return (self.A, self.B, self.C_proxy, self.I_kwt, self.B_group, E)

    def receive_signature(self, signature):
        self.signatures.append(signature)
        #print("Signature received")

    def receive_C_proxy(self, C_proxy):
        self.C_proxy = C_proxy

    def receive_I_kwt(self, I_kwt):
        self.I_kwt = I_kwt

    def select_actual_proxy_signers(self, amount, threshold):
        #print("UG' selected")
        return random.sample(range(0, amount - 1), threshold + 1) # jesli mamy 5 proxy signerów to wybieramy od 0 do 4, na razie wybieramy takich signerów o jednego wiecej niz wynosi threshold, potem jakoś to zmienić

class Verifier:
    def __init__(self):
        print("Instance of Verifier created")

    def verify_A_P(self, signature, public_parameters, id, m):
        G = public_parameters[0]
        msg = str(id) + m
        P_m = G.hashG1(msg.encode('utf-8'))
        if G.pair(signature[0], public_parameters[2]) == G.pair(P_m, signature[1]):
            print("Zgadza sie")
        else:
            print("Nie zgadza sie")

    def verify_C_proxy_P(self, signature, public_parameters, id, P_ver):
        G = public_parameters[0]
        h = hash(signature[3]) % 4294967295 #to powinno liczyc pkg
        hP_ver = P_ver.mul(h)
        R = hP_ver.add(signature[1])
        Q_id = public_parameters[5](id)
        if G.pair(signature[2], public_parameters[2]) == G.pair(Q_id, R):
            print("Zgadza sie")
        else:
            print("Nie zgadza sie")

    def verify_E_P(self, signature, public_parameters, H):
        G = public_parameters[0]
        E = signature[5][0]
        for ele in signature[5][1:]:
            E = E.add(ele)
        R = G.pair(H[0], signature[4][0])
        for i, u in enumerate(H[1:], start = 1):
            R = R.mul(G.pair(H[i], signature[4][i]))
        if G.pair(E, public_parameters[2]) == R:
            print("Zgadza sie")
        else:
            print("Nie zgadza się")



    def check_validity_of_I_w(self, P_ver, sig, pkg, id):
        received_sig = pkg.calculate_signature(id)
        return received_sig == sig

pkg = PrivateKeyGenerator()
def setup():
    pkg.generate_groups()
    pkg.choose_generator()
    pkg.select_s(7) #7 na razie nieużywane
    pkg.set_P_pub()
    pkg.compute_public_parameters()

setup()

user = User(1)
def extract():
    user.select_k()
    user.compute_commitment(pkg.return_P())
    user.receive_P_ver(pkg.compute_P_ver(user.send_committment()))
    user.receive_pkg_signature(pkg.compute_signature(user.id))
    user.compute_D_proxy(pkg.compute_sQ_id(user.id))

extract()

n = 5
threshold = 3
proxy_users = [User(i) for i in range (2, n+2)]
#for u in proxy_users:
    #print(u.id)

def delegate():
    user.compute_warrant(proxy_users)
    user.compute_D_kwt(pkg.hash_function_to_zq(user.compute_I_kwt(3)))

delegate()

def keyshare():
    user.select_x_id(2137)
    user.shamir_split(user.x_id, threshold, n, pkg.return_P())
    #print("*********" + str(user.x_id))
    for i, u in enumerate(proxy_users):
        u.receive_share_and_committment(user.send_share(i), user.send_aiP())
        #u.verify_share_correctness() na razie pomijam bo nie działa
        user.compute_B(pkg.return_P())
    user.compute_C_proxy(pkg.hash_function_to_group(user.id), 4294967295)

keyshare()

message = "test message"
print("Message: " + message)

proxy_signers_prim = []

def proxy_sign():
    for u in proxy_users:
        u.compute_A_i(message, pkg.return_G())
        u.receive_C_proxy(user.C_proxy)
        u.receive_I_kwt(user.I_kwt)
        u.compute_A_pg(user.x_id) #tymczasowo
        u.receive_B(user.B)
    tmp_list = user.select_actual_proxy_signers(len(proxy_users), threshold)
    #print("tmp_list: " + str(tmp_list))

    for i in tmp_list:
        proxy_signers_prim.append(proxy_users[i])

    for u in proxy_signers_prim:
        #u.verify_Ai_correctness() # na razie pomijam weryfikowanie
        u.compute_x_i()
        u.compute_Aprim_i(pkg.return_G(), message, user.warrant, threshold, proxy_signers_prim)
        u.compute_B_i(pkg.return_P())
        #u.compute_E()
        for u2 in proxy_signers_prim: #broadcast Aprimi
            if u2.id != u.id:
                u2.receive_Aprim_i(u.send_Aprim_i())
            u2.receive_B_i(u.send_B_i())
            #u.verify_correctness_Aprimi() na razie pomijam weryfikowanie poprawności
    for u in proxy_signers_prim:
        user.receive_signature(u.compute_complete_signature())

proxy_sign()
public_board = PublicBoard()
public_board.receive_parameters(user.signatures[0], pkg.public_parameters, proxy_signers_prim[0].id, message, pkg.P_ver, user.id)

verifier = Verifier()
def verify():

    P_Ms = [] #te P_Ms tez trzeba jeszcze przemyśleć
    for u in proxy_signers_prim:
        P_Ms.append(u.P_M)

    verifier.verify_A_P(public_board.signature, public_board.public_parameters, public_board.pg_user_id, public_board.m)
    verifier.verify_C_proxy_P(public_board.signature, public_board.public_parameters, public_board.user_id, public_board.P_ver)
    verifier.verify_E_P(public_board.signature, public_board.public_parameters, P_Ms)

verify()