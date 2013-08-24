from M2Crypto import RSA, X509, EVP, m2

import hashlib
import hmac
import struct
import socket
import ssl
import sys

HOST = "github.com"
PORT = 443

TIMEOUT = 10

SSL_VERSION = "\x03\x01"  # tls 1.0, we support only this version for the
                          # simplicity of code

TLS_DHE_RSA_WITH_AES_256_CBC_SHA = "\x00\x39"

CHANGE_CIPHER = "\x14"
ALERT = "\x15"
HANDSHAKE = "\x16"
APPLICATION_DATA = "\x17"

# OPENSSL CONSTS
ENC = 1
DEC = 0


# CYPHER INFO HELPERS
def get_key_len(algo):
    keylens = {TLS_DHE_RSA_WITH_AES_256_CBC_SHA: 32}
    return keylens[algo]


def get_iv_len(algo):
    ivlens = {TLS_DHE_RSA_WITH_AES_256_CBC_SHA: 16}
    return ivlens[algo]


def get_mac_len(algo):
    maclens = {TLS_DHE_RSA_WITH_AES_256_CBC_SHA: 20}
    return maclens[algo]


# BYTE MANIPULATION HELPERS
def bytes_to_num(bytes):
    num = 0
    for byte in bytes:
        num <<= 8
        num += ord(byte)
    return num


def recv_num_bytes(s, num):
    ret = ""

    while len(ret) < num:
        ret += s.recv(min(4096, num - len(ret)))

    assert len(ret) == num

    return ret


# NETWORK AND LOW LEVEL SSL PROTOCOL HELPERS
def num_to_bytes(num, bytes_len=None):
    bytes = []
    assert num >= 0
    while num > 0:
        bytes.append(chr(num % 256))
        num >>= 8

    ans = ''.join(reversed(bytes))

    if bytes_len is None:
        return ans
    else:
        assert len(ans) <= bytes_len
        return "\x00" * (bytes_len - len(ans)) + ans


def recv_tls(s):
    rec_type = recv_num_bytes(s, 1)

    tls_version = recv_num_bytes(s, 2)
    assert tls_version == SSL_VERSION

    rec_len = bytes_to_num(recv_num_bytes(s, 2))
    rec = recv_num_bytes(s, rec_len)

    return rec_type, rec


def send_tls(s, rec_type, msg):
    tls_record = rec_type + SSL_VERSION + num_to_bytes(len(msg), 2) + msg
    s.sendall(tls_record)


# MESSAGE AUTENTICATION CODES AND HASHING HELPERS
def compute_prf_hash(data, key, hash_len):
    "Computes a very strange hash"

    part1 = key[:len(key) // 2]
    part2 = key[len(key) // 2:]

    md5_hash = bytearray()

    hash1 = hmac.new(part1, data, hashlib.md5).digest()

    while len(md5_hash) < hash_len:
        md5_hash += hmac.new(part1, hash1 + data, hashlib.md5).digest()
        hash1 = hmac.new(part1, hash1, hashlib.md5).digest()
    md5_hash = md5_hash[:hash_len]

    sha_hash = bytearray()

    hash2 = hmac.new(part2, data, hashlib.sha1).digest()

    while len(sha_hash) < hash_len:
        sha_hash += hmac.new(part2, hash2 + data, hashlib.sha1).digest()
        hash2 = hmac.new(part2, hash2, hashlib.sha1).digest()
    sha_hash = sha_hash[:hash_len]

    # now we just need to xor md5_hash and sha_hash
    xored = bytearray("\x00" * hash_len)
    for i in range(hash_len):
        xored[i] = md5_hash[i] ^ (sha_hash[i])
    xored = bytes(xored)

    return xored


def calc_mac(mac_key, seq_num, rec_type, data):
    header = num_to_bytes(seq_num, 8) + rec_type + SSL_VERSION + num_to_bytes(len(data), 2)

    # print("mac_key %s" % mac_key.encode("hex"))
    # print("header %s" % header.encode("hex"))
    # print("data %s" % data.encode("hex"))

    mac = hmac.new(mac_key, header + data, hashlib.sha1).digest()
    return mac


def pad_data(data, block_len):
    paddinglen = block_len - (len(data) % block_len)
    return data + chr(paddinglen - 1) * paddinglen


def unpad_data(data, block_len):
    paddinglen = ord(data[-1]) + 1
    assert paddinglen <= block_len
    return data[:-paddinglen]


# PACKET GENERATORS AND HANDLERS
def gen_client_hello(client_random):
    CLIENT_HELLO = "\x01"

    client_version = SSL_VERSION  # tls 1.0

    unix_time = client_random[:4]
    random_bytes = client_random[4:]

    session_id_len = "\x00"
    session_id = ""

    cipher_suites_len = num_to_bytes(2, 2)  # only TLS_DHE_RSA_WITH_AES_256_CBC_SHA

    compression_method_len = "\x01"
    compression_method = "\x00"  # no compression

    client_hello_data = (client_version + unix_time + random_bytes +
                         session_id_len + session_id + cipher_suites_len +
                         TLS_DHE_RSA_WITH_AES_256_CBC_SHA +
                         compression_method_len + compression_method)

    client_hello_tlv = CLIENT_HELLO + num_to_bytes(len(client_hello_data), 3) + client_hello_data

    return client_hello_tlv


def handle_server_hello(server_hello):
    handshake_type = server_hello[0]

    SERVER_HELLO = "\x02"
    assert handshake_type == SERVER_HELLO

    server_hello_len = server_hello[1:4]
    server_version = server_hello[4:6]

    unix_time = server_hello[6:10]
    random_bytes = server_hello[10:38]
    server_random = unix_time + random_bytes

    session_id_len = bytes_to_num(server_hello[38:39])
    session_id = server_hello[39: 39 + session_id_len]

    cipher_suite = server_hello[39 + session_id_len: 39 + session_id_len + 2]
    compression_method = server_hello[39 + session_id_len + 2: 39 + session_id_len + 3]

    return server_random, session_id


def handle_server_cert(server_cert_data):
    handshake_type = server_cert_data[0]

    CERTIFICATE = "\x0b"
    assert handshake_type == CERTIFICATE

    certificate_field_len = bytes_to_num(server_cert_data[1:4])
    certificates_len = bytes_to_num(server_cert_data[4:7])

    certificates = []

    cert_string_left = server_cert_data[7: 7 + certificates_len]
    while cert_string_left:
        cert_len = bytes_to_num(cert_string_left[:3])

        certificates.append(cert_string_left[3: 3 + cert_len])

        cert_string_left = cert_string_left[3 + cert_len:]

    return certificates


def handle_server_key_exchange(server_key_exchange_data):
    handshake_type = server_key_exchange_data[0]

    SERVER_KEY_EXCHANGE = "\x0c"
    assert handshake_type == SERVER_KEY_EXCHANGE

    server_key_exchange_data_len = bytes_to_num(server_key_exchange_data[1: 4])

    dh_p_len = bytes_to_num(server_key_exchange_data[4: 6])
    dh_p = bytes_to_num(server_key_exchange_data[6: 6 + dh_p_len])

    cur_pos = 6 + dh_p_len  # curpos is just for shorting
    dh_g_len = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + 2])

    cur_pos += 2
    dh_g = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + dh_g_len])

    cur_pos += dh_g_len
    dh_Ys_len = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + 2])  # (g^X mod p)

    cur_pos += 2
    dh_Ys = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + dh_Ys_len])

    cur_pos += dh_Ys_len
    dh_sign_len = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + 2])

    cur_pos += 2
    dh_sign = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + dh_sign_len])

    return dh_p, dh_g, dh_Ys, dh_sign


def validate_signature(rsa, client_random, server_random, dh_p, dh_g, dh_Ys, dh_sign):
    dh_p_raw = num_to_bytes(dh_p)
    dh_g_raw = num_to_bytes(dh_g)
    dh_Ys_raw = num_to_bytes(dh_Ys)

    text = client_random + server_random
    text += num_to_bytes(len(dh_p_raw), 2) + dh_p_raw
    text += num_to_bytes(len(dh_g_raw), 2) + dh_g_raw
    text += num_to_bytes(len(dh_Ys_raw), 2) + dh_Ys_raw

    md5_hash = hashlib.md5(text).digest()
    sha_hash = hashlib.sha1(text).digest()

    encrypted_premaster = rsa.public_encrypt(md5_hash + sha_hash, RSA.pkcs1_oaep_padding)

    # Dirty hack: M2Crypto have no md5+sha1 support. But openssl has it since 2002
    # I filed a feature request to M2Crypto, but now we add explicitly md5_sha1 const in m2crypto
    m2.NID_md5_sha1 = 114
    try:
        rsa.verify(md5_hash + sha_hash, num_to_bytes(dh_sign), algo="md5_sha1")
        return True
    except RSA.RSAError:
        return False


def gen_client_key_exchange(my_dh_pub):
    CLIENT_KEY_EXCHANGE = "\x10"

    dh_pubkey = num_to_bytes(my_dh_pub)
    dh_params = num_to_bytes(len(dh_pubkey), 2) + dh_pubkey

    client_key_exchange_tlv = CLIENT_KEY_EXCHANGE + num_to_bytes(len(dh_params), 3) + dh_params

    return client_key_exchange_tlv


def compute_master_secret(client_random, server_random, our_secret):
    SSL_MAX_MASTER_KEY_LENGTH = 48
    return compute_prf_hash("master secret" + client_random + server_random,
                            our_secret, SSL_MAX_MASTER_KEY_LENGTH)


def compute_key_block(master_secret, key_block_len):
    return compute_prf_hash("key expansion" + server_random + client_random,
                            master_secret, key_block_len)


def gen_change_cipher():
    CHANGE_CIPHER_SPEC_MSG = "\x01"
    return CHANGE_CIPHER_SPEC_MSG


def gen_encrypted_hangshake_msg(encryptor, seq_num, mac_key, client_finish_val):
    FINISHED = "\x14"

    msg = FINISHED + num_to_bytes(len(client_finish_val), 3) + client_finish_val
    raw_msg = msg

    msg += calc_mac(mac_key, seq_num, HANDSHAKE, msg)

    encrypted_msg = encryptor.update(pad_data(msg, 16))  # for aes
    encrypted_msg += encryptor.final()

    return raw_msg, encrypted_msg


def handle_server_change_cipher(server_change_cipher):
    CHANGE_CIPHER_SPEC_MSG = "\x01"
    assert server_change_cipher == CHANGE_CIPHER_SPEC_MSG


def handle_encrypted_hangshake_msg(decryptor, seq_num, mac_key,
                                   computed_server_finish_val, encrypted_msg):
    msg = decryptor.update(encrypted_msg)
    msg += decryptor.final()
    msg = unpad_data(msg, 16)

    mac_len = get_mac_len(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)

    payload = msg[:-mac_len]
    mac = msg[-mac_len:]

    # we use HANDSHAKE as record type because this function will be called if
    # the record type is HANDSHAKE

    computed_mac = calc_mac(mac_key, seq_num, HANDSHAKE, payload)

    mac_is_valid = mac == computed_mac

    handshake_type = payload[0]

    FINISHED = "\x14"
    assert handshake_type == FINISHED

    server_finish_val_len = bytes_to_num(payload[1:4])
    server_finish_val = payload[4:]
    assert len(server_finish_val) == server_finish_val_len

    server_finish_val_is_valid = computed_server_finish_val == server_finish_val
    return mac_is_valid, server_finish_val_is_valid


def gen_encrypted_appdata_msg(encryptor, seq_num, mac_key, msg):
    msg += calc_mac(mac_key, seq_num, APPLICATION_DATA, msg)

    encrypted_msg = encryptor.update(pad_data(msg, 16))  # for aes
    encrypted_msg += encryptor.final()

    return encrypted_msg


def handle_encrypted_appdata_msg(decryptor, seq_num, mac_key, encrypted_msg):
    msg = decryptor.update(encrypted_msg)
    msg += decryptor.final()
    msg = unpad_data(msg, 16)

    mac_len = get_mac_len(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)

    payload = msg[:-mac_len]
    mac = msg[-mac_len:]

    computed_mac = calc_mac(mac_key, seq_num, APPLICATION_DATA, payload)

    mac_is_valid = mac == computed_mac

    return mac_is_valid, payload


def handle_encrypted_alert(decryptor, seq_num, mac_key, encrypted_msg):
    msg = decryptor.update(encrypted_msg)
    msg += decryptor.final()
    msg = unpad_data(msg, 16)

    mac_len = get_mac_len(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)

    payload = msg[:-mac_len]
    mac = msg[-mac_len:]

    alert_level, alert_description = payload

    computed_mac = calc_mac(mac_key, seq_num, ALERT, payload)

    mac_is_valid = mac == computed_mac

    return mac_is_valid, alert_level, alert_description


print("Connecting to %s:%d" % (HOST, PORT))
s = socket.create_connection((HOST, PORT), TIMEOUT)
print("Connected")

print("Handshake: sending a client hello")
client_random = "\xAB" * 32
print("Client random: %s" % client_random.encode("hex"))

client_hello = gen_client_hello(client_random)
send_tls(s, HANDSHAKE, client_hello)

print("Handshake: receiving a server hello")
rec_type, server_hello = recv_tls(s)

if rec_type == ALERT:
    print("Server sent us ALERT, it probably doesn't support TLS_DHE_RSA_WITH_AES_256_CBC_SHA algo")
    sys.exit(1)

assert rec_type == HANDSHAKE

server_random, session_id = handle_server_hello(server_hello)
print("Server random: %s" % server_random.encode("hex"))
print("Session id: %s" % session_id.encode("hex"))

print("Handshake: receiving a server certs")
rec_type, server_cert_data = recv_tls(s)
assert rec_type == HANDSHAKE

certs = handle_server_cert(server_cert_data)
print("Got %d certs" % len(certs))

rsa = X509.load_cert_string(certs[0], format=X509.FORMAT_DER).get_pubkey().get_rsa()

print("Handshake: receiving a server key exchange")
rec_type, server_key_exchange_data = recv_tls(s)
assert rec_type == HANDSHAKE

dh_p, dh_g, dh_Ys, dh_sign = handle_server_key_exchange(server_key_exchange_data)
print("DH prime: %s" % dh_p)
print("DH generator: %s" % dh_g)
print("DH pubkey: %s" % dh_Ys)
print("DH signature: %s" % dh_sign)

sign_is_valid = validate_signature(rsa, client_random, server_random, dh_p, dh_g, dh_Ys, dh_sign)
if sign_is_valid:
    print("Server DH signature is VALID")
else:
    print("Server DH signature is INVALID!!!")

print("Handshake: receiving a server hello done")
rec_type, handshake_data = recv_tls(s)
assert rec_type == HANDSHAKE

my_secretY = 10

my_pub = pow(dh_g, my_secretY, dh_p)
print("My DH pubkey: %s" % my_pub)

our_secret = pow(dh_Ys, my_secretY, dh_p)
print("Our common DH secret is: %s" % our_secret)

print("Handshake: sending a client key exchange")
client_key_exchange_data = gen_client_key_exchange(my_pub)
send_tls(s, HANDSHAKE, client_key_exchange_data)

our_master_secret = compute_master_secret(client_random, server_random, num_to_bytes(our_secret))
print("Our master secret: %s" % our_master_secret.encode("hex"))

key_block_len = (get_key_len(TLS_DHE_RSA_WITH_AES_256_CBC_SHA) +
                 get_iv_len(TLS_DHE_RSA_WITH_AES_256_CBC_SHA) +
                 get_mac_len(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
                 ) * 2
key_block = compute_key_block(our_master_secret, key_block_len)

print("Our keyblock: %s" % key_block.encode("hex"))

# hack, valid only on TLS_DHE_RSA_WITH_AES_256_CBC_SHA

client_write_mac_key = key_block[:20]
server_write_mac_key = key_block[20:40]
client_write_key = key_block[40: 72]
server_write_key = key_block[72: 104]
client_write_iv = key_block[104: 120]
server_write_iv = key_block[120: 136]

print("Mac key: %s, key: %s, iv: %s" % (client_write_mac_key.encode("hex"),
                                        client_write_key.encode("hex"),
                                        client_write_iv.encode("hex")))

all_handshake_pkts = (client_hello + server_hello + server_cert_data +
                      server_key_exchange_data + handshake_data +
                      client_key_exchange_data)

all_handshake_pkts_md5 = hashlib.md5(all_handshake_pkts).digest()
all_handshake_pkts_sha1 = hashlib.sha1(all_handshake_pkts).digest()

client_finish_val = compute_prf_hash("client finished" + all_handshake_pkts_md5 +
                                     all_handshake_pkts_sha1, our_master_secret, 12)

print("Client finish val: %s" % client_finish_val.encode("hex"))

encryptor = EVP.Cipher(alg='aes_256_cbc', key=client_write_key, iv=client_write_iv, op=ENC, padding=0)
decryptor = EVP.Cipher(alg='aes_256_cbc', key=server_write_key, iv=server_write_iv, op=DEC, padding=0)

client_seq_num = 0  # for use in mac calculation
server_seq_num = 0

print("Handshake: sending a change cipher msg")
change_cipher = gen_change_cipher()
send_tls(s, CHANGE_CIPHER, change_cipher)

# All client messages beyond this point are crypted

print("Handshake: sending an encrypted handshake msg")
raw_msg, encrypted_hangshake_msg = gen_encrypted_hangshake_msg(encryptor, client_seq_num,
                                                               client_write_mac_key,
                                                               client_finish_val)
send_tls(s, HANDSHAKE, encrypted_hangshake_msg)
client_seq_num += 1

all_handshake_pkts += raw_msg
all_handshake_pkts_md5 = hashlib.md5(all_handshake_pkts).digest()
all_handshake_pkts_sha1 = hashlib.sha1(all_handshake_pkts).digest()

server_finish_val = compute_prf_hash("server finished" +
                                     all_handshake_pkts_md5 + all_handshake_pkts_sha1,
                                     our_master_secret, 12)
print("Server finish val: %s" % server_finish_val.encode("hex"))


print("Handshake: receiving a change cipher msg")
rec_type, server_change_cipher = recv_tls(s)
assert rec_type == CHANGE_CIPHER

handle_server_change_cipher(server_change_cipher)

print("Handshake: receiving an encrypted handshake msg")
rec_type, server_encrypted_hangshake_msg = recv_tls(s)

mac_is_valid, server_finish_val_is_valid = (
    handle_encrypted_hangshake_msg(
        decryptor, server_seq_num, server_write_mac_key,
        server_finish_val, server_encrypted_hangshake_msg)
)
server_seq_num += 1

print("Msg mac is valid: %s, server finish val is valid: %s" % (
      mac_is_valid, server_finish_val_is_valid))
print("Handshake finished")

# the rest is just for fun
print("Sending GET /")
encrypted_msg = gen_encrypted_appdata_msg(encryptor, client_seq_num, client_write_mac_key, "GET /\n")
send_tls(s, APPLICATION_DATA, encrypted_msg)
client_seq_num += 1

print("Receiving an answer")

while True:
    rec_type, server_encrypted_msg = recv_tls(s)
    if rec_type == APPLICATION_DATA:
        mac_is_valid, msg = handle_encrypted_appdata_msg(decryptor, server_seq_num,
                                                         server_write_mac_key,
                                                         server_encrypted_msg)
        server_seq_num += 1
        if not mac_is_valid:
            print("Mac is invalid!!!")
        print("Got: %s" % msg)
    elif rec_type == ALERT:
        mac_is_valid, alert_level, alert_description = handle_encrypted_alert(decryptor,
                                                                              server_seq_num,
                                                                              server_write_mac_key,
                                                                              server_encrypted_msg)
        server_seq_num += 1
        if not mac_is_valid:
            print("Mac is invalid!!!")

        print("Got alert level: %s, description: %s" % (ord(alert_level), ord(alert_description)))
        if alert_description == "\x00":
            print("Server sent close_notify, no waiting for more data")
            break
    else:
        print("Got msg with unknown rec_type")
