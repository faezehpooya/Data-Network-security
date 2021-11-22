from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
import base64, os
from base64 import b64decode
from collections import Counter


def generate_secret_key_for_AES_cipher():
    AES_key_length =   32
    secret_key = os.urandom(AES_key_length)
    encoded_secret_key = base64.b64encode(secret_key)
    return encoded_secret_key


def encrypt_message(private_msg, encoded_secret_key, padding_character):
    secret_key = base64.b64decode(encoded_secret_key)
    cipher = AES.new(secret_key, AES.MODE_ECB)
    padded_private_msg = private_msg + (padding_character * ((16 - len(private_msg)) % 16))
    encrypted_msg = cipher.encrypt(padded_private_msg.encode('UTF-8'))
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, encoded_secret_key, padding_character):
    secret_key = base64.b64decode(encoded_secret_key)
    encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    cipher = AES.new(secret_key, AES.MODE_ECB)
    decrypted_msg = cipher.decrypt(encrypted_msg)
    unpadded_private_msg = decrypted_msg.rstrip(padding_character.encode('UTF-8'))
    return unpadded_private_msg

def encrypt(message, key):
    encrypter = PKCS1_OAEP.new(key)
    encrypted = encrypter.encrypt(message.encode('UTF-8'))
    return encrypted


def decrypt(message, key_pair):
    decrypter = PKCS1_OAEP.new(key_pair)
    decrypted = decrypter.decrypt(message)
    return decrypted


def encrypt_multi_packet_1(message, key):
    encrypter = PKCS1_OAEP.new(key)
    mlen = len(message) // (len(message)-80)
    encrypts = []
    for i in range((len(message)-80)):
        msg = message[i * mlen: (i + 1) * mlen]
        encrypted = encrypter.encrypt(msg)
        encrypts.append(encrypted)

    msg = message[ (len(message)-80) * mlen:]

    encrypted = encrypter.encrypt(msg)
    encrypts.append(encrypted)
    return encrypts


def decrypt_multi_packet(messages, key_pair):
    decrypter = PKCS1_OAEP.new(key_pair)
    decrypted_message = b""
    for message in messages:
        decrypted = decrypter.decrypt(message)
        decrypted_message += (decrypted)
    return decrypted_message

def sign_multi_packet(messages, key):
    signs = []
    for message in messages:
        s = sign(message, key)
        signs.append(s)
    return signs


def sign(message, key):
    signer = PKCS1_v1_5.new(key)
    digest = SHA512.new()
    digest.update(message)
    s=signer.sign(digest)
    return s


def verify(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA512.new()
    digest.update(message)
    return signer.verify(digest, signature)


def verify_multi_packet(messages, signatures, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA512.new()
    for message, signature in list(zip(messages, signatures)):
        digest = SHA512.new()
        digest.update(message)
        v = signer.verify(digest, signature)
        if not v:
            return v
    return True

class CA:
    def __init__(self):
        print("CA created...")
        self.key_pair = RSA.generate(1024)
        self.key_pair_dict = dict()
        self.key_pair_dict[("CA")]=self.key_pair

    def generate_key(self,name):
        key=RSA.generate(1024)
        self.key_pair_dict[(name)]=key
        return key

    def get_pub_key_of(self, item):
        if (item) in self.key_pair_dict.keys():
            if type(self.key_pair_dict[item]) == list:
                return (self.key_pair_dict[(item)])[1].publickey()
            else:
                return self.key_pair_dict[item].publickey()
        else:
            print("there is not key created for " ,item ," yet!!")
            return None

    def recieve_from_voter_save_in_database(self, message):
        print("recieve_from_voter_save_in_database ",end=" ")
        decrypted_message = str(decrypt(message,self.key_pair))
        print("message is: ",decrypted_message)
        d = decrypted_message.split(", ")
        v_id = str(d[0])[2:]
        v_cert = str(d[1])[:-1]
        if v_id not in self.key_pair_dict.keys():
            print("Generating key for voter with id ",v_id)
            key = RSA.generate(1024)
            self.key_pair_dict[v_id]=[v_cert,key]

    def ca_recieve_from_as_send_to_as(self, message):
        print("ca_recieve_from_as_send_to_as")
        encrypted_message, signature = message
        v = verify(encrypted_message, signature, self.key_pair_dict[("AS")].publickey())
        if v:
            print("message verified")
            decrypted_msg = decrypt(encrypted_message, self.key_pair)
            print("message is : ",decrypted_msg)
            d = decrypted_msg.split(b", ")
            v_id = str(d[0])[4: -1]
            v_cert = str(d[1])[2:-2]
            if (v_id) in self.key_pair_dict.keys():
                data = self.key_pair_dict[(v_id)]
                if data[0] == v_cert:
                    my_message =(data[1].exportKey())
                    encrypted_key = encrypt_multi_packet_1(my_message, self.key_pair_dict[("AS")].publickey())
                    sign_e_key = sign_multi_packet(encrypted_key, self.key_pair)
                    second_message = v_id
                    encrypted_v_id = encrypt(second_message, self.key_pair_dict[("AS")].publickey())
                    sign_e_v_id = sign(encrypted_v_id, self.key_pair)

                    return (encrypted_key, sign_e_key, encrypted_v_id, sign_e_v_id)

        return None


class AS:
    def __init__(self, key_pair):
        self.key_pair = key_pair
        self.symmetric_keys = dict()
        self.invalid_user_v_id_to_vote=[("1234","1234_a"),("4567","4567_1"),("9876","9876_a")]


    def  as_recieve_from_voter_send_to_ca(self, message, ca_pub_key):
        print("as_recieve_from_voter_send_to_ca")
        decrypted_message = str(decrypt(message,self.key_pair))
        print("message is : ",decrypted_message )
        d = decrypted_message.split(", ")
        v_id = str(d[0])[2:]
        v_cert = str(d[1])[:-1]
        if (v_id,v_cert) not in self.invalid_user_v_id_to_vote:
            encrypted_message = encrypt(decrypted_message, ca_pub_key)
            signature = sign(encrypted_message, self.key_pair)
            return [encrypted_message, signature]
        else:
            print("this user with v_id " , v_id ,"and v_cert ", v_cert ,"has not permission to vote")
            return None

    def add_symmetric_key(self, v_id, symmetric_key_with_as):
        self.symmetric_keys[v_id] = symmetric_key_with_as

    def as_recieve_from_ca_send_to_voter(self, messages_signatures, ca_pub_key):
        print("as_recieve_from_ca_send_to_voter")
        encrypted_messages, signatures, encrypted_v_id, signed_v_id = messages_signatures
        v1 = verify_multi_packet(encrypted_messages, signatures, ca_pub_key)
        v2 = verify(encrypted_v_id, signed_v_id, ca_pub_key)

        if v1 and v2:
            print("message verified")
            msg = decrypt_multi_packet(encrypted_messages, self.key_pair)
            print("message is : " ,msg )
            code = decrypt(encrypted_v_id, self.key_pair)
            v_id = str(code)[2: -1]
            secret_key = self.symmetric_keys[v_id]
            key = RSA.importKey(msg)
            voter_pub_key = RSA.importKey(key.publickey().exportKey())
            T = encrypt_multi_packet_1((sign(code, self.key_pair)), voter_pub_key)
            T=b"".join(T)
            padding_character = "-"
            encrypted_T = encrypt_message(str(T), secret_key, padding_character)
            signed_encrypted_T = sign(encrypted_T, self.key_pair)
            encrypted_v_id = encrypt_message(v_id, secret_key, padding_character)
            signed_encrypted_v_id = sign(encrypted_v_id, self.key_pair)
            encrypted_key_pair = encrypt_message(str(key.exportKey()), secret_key, padding_character)
            signed_encrypted_key_pair = sign(encrypted_key_pair, self.key_pair)
            return ([encrypted_v_id, encrypted_key_pair, encrypted_T], [signed_encrypted_v_id, signed_encrypted_key_pair, signed_encrypted_T])
        return None

class VS:
    def __init__(self, key_pair):
        self.key_pair = key_pair
        self.voters=[]
        self.voted=[]

    def vs_recieve_from_voter_send_to_voter(self,message,voter_pub_key):
        print("vs recieve_from_voter_send_to_voter")
        messages, signs = message
        v = verify(messages[0], signs, voter_pub_key)
        if v:
            print("message verified")
            i_code_voted =str(decrypt(messages[0], self.key_pair).decode('utf-8'))
            T = str(decrypt_multi_packet(messages[1],self.key_pair).decode('utf-8'))
            print("message is : ",i_code_voted + "," + T)
            i_code_voted = i_code_voted.split(",")
            i_code=i_code_voted[0]
            voted=i_code_voted[1]
            self.voters.append(i_code)
            self.voted.append(voted)
            message=encrypt(str(voted),voter_pub_key)
            s=sign(message,self.key_pair)
            return (message,s)
        return None

    def counting(self):
        d=Counter(self.voted)
        print(d)
        return max(d,key=d.get)




class Voter:
    def __init__(self, v_id, v_cert,voted):
        self.v_id = v_id
        self.v_cert = v_cert
        self.symmetric_key_with_as = generate_secret_key_for_AES_cipher()
        self.voted=voted
        self.key_pair=None

    def get_auth_symmetric_key(self):
        return self.v_id, self.symmetric_key_with_as

    def voter_send_to_ca(self, ca_pub_key):
        message = str(self.v_id) + ", " + str(self.v_cert)
        print("voter_send_to_ca.message is : ",message)
        return encrypt(message, ca_pub_key)

    def voter_send_to_as(self, as_pub_key):
        message = str(self.v_id) + ", " + str(self.v_cert)
        print("voter_send_to_as.message is :",message)
        return encrypt(message,as_pub_key)

    def voter_recieve_from_as_send_to_vs(self, msg, as_pub_key,vs_pub_key):
        print("voter_recieve_from_as_send_to_vs")
        messages, signs = msg
        v = verify_multi_packet(messages, signs, as_pub_key)
        if v:
            print("message verified")
            padding_character = "-"
            v_id =decrypt_message(messages[0], self.symmetric_key_with_as, padding_character).decode('utf-8')
            key_pair = decrypt_message(messages[1], self.symmetric_key_with_as, padding_character)
            T = decrypt_message(messages[2], self.symmetric_key_with_as, padding_character).decode('utf-8')
            print("message is :",v_id + "," + str(key_pair) + "," +T)
            key_pair = ((key_pair)[4: -2])
            key_pair=str(key_pair)
            orgstr=key_pair[34:-32]
            key_pair = orgstr.replace('\\n' ,"\n")
            key_pair=bytes(key_pair, 'utf-8')
            keyDER = b64decode(key_pair)
            key = RSA.importKey(keyDER)
            voter_key=key.exportKey()
            self.key_pair=key
            i_code_voted=str(self.v_id) +"," +str(self.voted)
            encrypted_i_code_voted=encrypt(i_code_voted,vs_pub_key)
            encrypted_T=encrypt_multi_packet_1(T.encode('utf-8'),vs_pub_key)
            sending_messages = [encrypted_i_code_voted,encrypted_T]
            signed_encrypted_i_code = sign(encrypted_i_code_voted,key)
            signs = signed_encrypted_i_code
            return (sending_messages,signs)
        return None

    def recieve_from_vs(self,message,vs_public_key):
        print("recieve_from_vs")
        messages, signs = message
        v = verify(messages, signs, vs_public_key)
        if v:
            print("message verified")
            voted = str(decrypt(messages, self.key_pair).decode('utf-8'))
            print("message is :",voted)
            if self.voted==voted:
                print("TRUE")
        return None


ca = CA()
as_server=AS(ca.generate_key("AS"))
vs_server=VS(ca.generate_key("VS"))
number_of_voters=5
voters_list=[]
candid=100
v_id=54321
vcert=str(v_id)
for i in range(number_of_voters):
    a=0
    if i%2==0:
        a=1
    voter1 = Voter(str(v_id+i),vcert+chr(i+97),str(candid+a))
    code, key = voter1.get_auth_symmetric_key()
    as_server.add_symmetric_key(code, key)
    m1 = voter1.voter_send_to_ca(ca.get_pub_key_of("CA"))
    if(m1==None):
        continue
    ca.recieve_from_voter_save_in_database(m1)
    m2 = voter1.voter_send_to_as(ca.get_pub_key_of("AS"))
    if(m2==None):
        continue
    m3 = as_server.as_recieve_from_voter_send_to_ca(m2,ca.get_pub_key_of("CA"))
    if(m3==None):
        continue
    m4 = ca.ca_recieve_from_as_send_to_as(m3)
    if(m4==None):
        continue
    m5 = as_server.as_recieve_from_ca_send_to_voter(m4,ca.get_pub_key_of("CA"))
    if(m5==None):
        continue
    m6 = voter1.voter_recieve_from_as_send_to_vs(m5,ca.get_pub_key_of("AS"), ca.get_pub_key_of("VS"))
    if(m6==None):
        continue
    m7 = vs_server.vs_recieve_from_voter_send_to_voter(m6,ca.get_pub_key_of(voter1.v_id))
    if(m7==None):
        continue
    voter1.recieve_from_vs(m7,ca.get_pub_key_of("VS"))

print("selected candid is :",vs_server.counting())
