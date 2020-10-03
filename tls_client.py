from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import hashlib
import hmac
import socket
import sys

HOST = "wiki.python.org"
PORT = 443

TIMEOUT = 10

# tls 1.2 for legacy reasons, tls 1.3 will be send in extensions as required
LEGACY_TLS_VERSION = b"\x03\x03"

TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = b"\x00\x9e"

CHANGE_CIPHER = b"\x14"
ALERT = b"\x15"
HANDSHAKE = b"\x16"
APPLICATION_DATA = b"\x17"

SHA1_ALG = 2
RSA_ALG = 1

TAG_LEN = 16


# CYPHER INFO HELPERS
def get_key_len(algo):
    keylens = {TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: 16}
    return keylens[algo]


def get_iv_len(algo):
    ivlens = {TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: 4}
    return ivlens[algo]


# BYTE MANIPULATION HELPERS
def bytes_to_num(b):
    return int.from_bytes(b, "big")


def num_to_bytes(num, bytes_len=None):
    assert num >= 0
    if bytes_len is None:
        bytes_len = (num.bit_length() + 7) // 8
    return int.to_bytes(num, bytes_len, "big")


# NETWORK AND LOW LEVEL TLS PROTOCOL HELPERS
def recv_num_bytes(s, num):
    ret = b""

    while len(ret) < num:
        data = s.recv(min(4096, num - len(ret)))
        if not data:
            raise BrokenPipeError
            break
        ret += data

    assert len(ret) == num

    return ret


def recv_tls(s):
    rec_type = recv_num_bytes(s, 1)

    LEGACY_tls_version = recv_num_bytes(s, 2)
    assert LEGACY_tls_version == LEGACY_TLS_VERSION

    rec_len = bytes_to_num(recv_num_bytes(s, 2))
    rec = recv_num_bytes(s, rec_len)

    return rec_type, rec


def send_tls(s, rec_type, msg):
    tls_record = rec_type + LEGACY_TLS_VERSION + num_to_bytes(len(msg), 2) + msg
    s.sendall(tls_record)


# MESSAGE AUTENTICATION CODES AND HASHING HELPERS
def compute_prf_hash(data, key, hash_len):
    sha256_result = bytearray()

    hmac_digest = hmac.new(key, data, hashlib.sha256).digest()

    while len(sha256_result) < hash_len:
        sha256_result += hmac.new(key, hmac_digest + data, hashlib.sha256).digest()
        hmac_digest = hmac.new(key, hmac_digest, hashlib.sha256).digest()
    sha256_result = sha256_result[:hash_len]

    return bytes(sha256_result)


# PACKET GENERATORS AND HANDLERS
def gen_client_hello(client_random):
    CLIENT_HELLO = b"\x01"

    client_version = LEGACY_TLS_VERSION  # tls 1.0, compat with old implementations

    unix_time = client_random[:4]
    random_bytes = client_random[4:]

    session_id_len = b"\x00"
    session_id = b""

    cipher_suites_len = num_to_bytes(2, 2)  # only TLS_DHE_RSA_WITH_AES_128_GCM_SHA256

    compression_method_len = b"\x01"
    compression_method = b"\x00"  # no compression

    extensions_len = b"\x00\x07"
    supported_versions = b"\x00\x2b"
    supported_versions_length = b"\x00\x03"
    another_supported_versions_length = b"\x02"
    tls1_3_version = b"\x03\x04"

    extensions = (extensions_len + supported_versions + supported_versions_length +
                  another_supported_versions_length + tls1_3_version)

    client_hello_data = (client_version + unix_time + random_bytes +
                         session_id_len + session_id + cipher_suites_len +
                         TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 +
                         compression_method_len + compression_method)

    client_hello_tlv = CLIENT_HELLO + num_to_bytes(len(client_hello_data), 3) + client_hello_data

    return client_hello_tlv


def handle_server_hello(server_hello):
    handshake_type = server_hello[0]

    SERVER_HELLO = 0x2
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

    CERTIFICATE = 0x0b
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

    SERVER_KEY_EXCHANGE = 0x0c
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
    dh_hash_alg = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + 1])
    assert dh_hash_alg == SHA1_ALG

    cur_pos += 1
    dh_sign_alg = bytes_to_num(server_key_exchange_data[cur_pos: cur_pos + 1])
    assert dh_sign_alg == RSA_ALG

    cur_pos += 1
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

    try:
        sha_hash = SHA1.new(text)
        pkcs1_15.new(rsa).verify(sha_hash, num_to_bytes(dh_sign))
        return True
    except ValueError:
        return False


def gen_client_key_exchange(my_dh_pub):
    CLIENT_KEY_EXCHANGE = b"\x10"

    dh_pubkey = num_to_bytes(my_dh_pub)
    dh_params = num_to_bytes(len(dh_pubkey), 2) + dh_pubkey

    client_key_exchange_tlv = CLIENT_KEY_EXCHANGE + num_to_bytes(len(dh_params), 3) + dh_params

    return client_key_exchange_tlv


def compute_master_secret(client_random, server_random, our_secret):
    TLS_MAX_MASTER_KEY_LENGTH = 48
    return compute_prf_hash(b"master secret" + client_random + server_random,
                            our_secret, TLS_MAX_MASTER_KEY_LENGTH)


def compute_key_block(master_secret, key_block_len):
    return compute_prf_hash(b"key expansion" + server_random + client_random,
                            master_secret, key_block_len)


def gen_change_cipher():
    CHANGE_CIPHER_SPEC_MSG = b"\x01"
    return CHANGE_CIPHER_SPEC_MSG


def do_authenticated_encryption(key, nonce_start, seq_num, msg_type, msg):
    # totaly not secure, it should be random
    nonce_end = b"\x00" * 8
    nonce = nonce_start + nonce_end

    data = num_to_bytes(seq_num, 8) + msg_type + LEGACY_TLS_VERSION + num_to_bytes(len(msg), 2)
    encrypted_msg = AESGCM(key).encrypt(nonce, msg, associated_data=data)
    return nonce_end + encrypted_msg


def do_authenticated_decryption(key, nonce_start, seq_num, msg_type, payload):
    nonce_end, msg, tag = payload[:8], payload[8:-TAG_LEN], payload[-TAG_LEN:]
    nonce = nonce_start + nonce_end

    data = num_to_bytes(seq_num, 8) + msg_type + LEGACY_TLS_VERSION + num_to_bytes(len(msg), 2)
    msg = AESGCM(key).decrypt(nonce, msg + tag, associated_data=data)
    return msg


def gen_encrypted_hangshake_msg(client_write_key, client_write_nonce_start, seq_num,
                                client_finish_val):
    FINISHED = b"\x14"

    msg = FINISHED + num_to_bytes(len(client_finish_val), 3) + client_finish_val
    encrypted_msg = do_authenticated_encryption(client_write_key, client_write_nonce_start,
                                                seq_num, HANDSHAKE, msg)
    return msg, encrypted_msg


def handle_server_change_cipher(server_change_cipher):
    CHANGE_CIPHER_SPEC_MSG = b"\x01"
    assert server_change_cipher == CHANGE_CIPHER_SPEC_MSG


def handle_encrypted_hangshake_msg(server_write_key, server_write_nonce_start, seq_num,
                                   encrypted_msg, computed_server_finish_val):
    # we use HANDSHAKE as record type because this function will be called if
    # the record type is HANDSHAKE
    payload = do_authenticated_decryption(server_write_key, server_write_nonce_start,
                                          seq_num, HANDSHAKE, encrypted_msg)

    handshake_type = payload[0]

    FINISHED = 0x14
    assert handshake_type == FINISHED

    server_finish_val_len = bytes_to_num(payload[1:4])
    server_finish_val = payload[4:]
    assert len(server_finish_val) == server_finish_val_len

    server_finish_val_is_valid = (computed_server_finish_val == server_finish_val)
    return server_finish_val_is_valid


def gen_encrypted_appdata_msg(client_write_key, client_write_nonce_start, seq_num, msg):
    encrypted_msg = do_authenticated_encryption(client_write_key, client_write_nonce_start,
                                                seq_num, APPLICATION_DATA, msg)
    return encrypted_msg


def handle_encrypted_appdata_msg(server_write_key, server_write_nonce_start, seq_num,
                                 encrypted_msg):
    payload = do_authenticated_decryption(server_write_key, server_write_nonce_start,
                                          seq_num, APPLICATION_DATA, encrypted_msg)
    return payload


def handle_encrypted_alert(server_write_key, server_write_nonce_start, seq_num, encrypted_msg):
    payload = do_authenticated_decryption(server_write_key, server_write_nonce_start,
                                          seq_num, ALERT, encrypted_msg)

    alert_level, alert_description = payload
    return alert_level, alert_description


print("Connecting to %s:%d" % (HOST, PORT))
s = socket.create_connection((HOST, PORT), TIMEOUT)
print("Connected")

print("Handshake: sending a client hello")
client_random = b"\xAB" * 32
print("Client random: %s" % client_random.hex())

client_hello = gen_client_hello(client_random)
send_tls(s, HANDSHAKE, client_hello)

print("Handshake: receiving a server hello")
rec_type, server_hello = recv_tls(s)

if rec_type == ALERT:
    print("Server sent us ALERT, it probably doesn't support " +
          "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 algo")
    sys.exit(1)

assert rec_type == HANDSHAKE

server_random, session_id = handle_server_hello(server_hello)
print("Server random: %s" % server_random.hex())
print("Session id: %s" % session_id.hex())

print("Handshake: receiving server certs")
rec_type, server_cert_data = recv_tls(s)
assert rec_type == HANDSHAKE

certs = handle_server_cert(server_cert_data)
print("Got %d certs" % len(certs))

rsa = RSA.import_key(certs[0])

print("Handshake: receiving a server key exchange")
rec_type, server_key_exchange_data = recv_tls(s)
assert rec_type == HANDSHAKE

dh_p, dh_g, dh_Ys, dh_sign = handle_server_key_exchange(server_key_exchange_data)
print("DH prime: %x" % dh_p)
print("DH generator: %x" % dh_g)
print("DH pubkey: %x" % dh_Ys)
print("DH signature: %x" % dh_sign)

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
print("My DH pubkey: %x" % my_pub)

our_secret = pow(dh_Ys, my_secretY, dh_p)
print("Our common DH secret (premaster secret) is: %x" % our_secret)

print("Handshake: sending a client key exchange")
client_key_exchange_data = gen_client_key_exchange(my_pub)
send_tls(s, HANDSHAKE, client_key_exchange_data)

our_master_secret = compute_master_secret(client_random, server_random, num_to_bytes(our_secret))
print("Our master key: %s" % our_master_secret.hex())

key_block_len = (get_key_len(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256) +
                 get_iv_len(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
                 ) * 2
key_block = compute_key_block(our_master_secret, key_block_len)

print("Our keyblock: %s" % key_block.hex())

# hack, valid only on TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
client_write_key = key_block[0:16]
server_write_key = key_block[16:32]
client_write_nonce_start = key_block[32:36]
server_write_nonce_start = key_block[36:40]

print("Client key: %s nonce_start: %s" % (client_write_key.hex(), client_write_nonce_start.hex()))
print("Server key: %s nonce_start: %s" % (server_write_key.hex(), server_write_nonce_start.hex()))

all_handshake_pkts = (client_hello + server_hello + server_cert_data +
                      server_key_exchange_data + handshake_data +
                      client_key_exchange_data)

all_handshake_pkts_sha256 = hashlib.sha256(all_handshake_pkts).digest()

client_finish_val = compute_prf_hash(b"client finished" +
                                     all_handshake_pkts_sha256, our_master_secret, 12)

print("Client finish val: %s" % client_finish_val.hex())

client_seq_num = 0  # for use in authenticated encryption
server_seq_num = 0

print("Handshake: sending a change cipher msg")
change_cipher = gen_change_cipher()
send_tls(s, CHANGE_CIPHER, change_cipher)

# All client messages beyond this point are encrypted

print("Handshake: sending an encrypted handshake msg")
raw_msg, encrypted_hangshake_msg = gen_encrypted_hangshake_msg(client_write_key,
                                                               client_write_nonce_start,
                                                               client_seq_num, client_finish_val)
send_tls(s, HANDSHAKE, encrypted_hangshake_msg)
client_seq_num += 1

all_handshake_pkts += raw_msg
all_handshake_pkts_sha256 = hashlib.sha256(all_handshake_pkts).digest()

server_finish_val = compute_prf_hash(b"server finished" +
                                     all_handshake_pkts_sha256,
                                     our_master_secret, 12)
print("Server finish val: %s" % server_finish_val.hex())

print("Handshake: receiving a change cipher msg")
rec_type, server_change_cipher = recv_tls(s)
assert rec_type == CHANGE_CIPHER

handle_server_change_cipher(server_change_cipher)

print("Handshake: receiving an encrypted handshake msg")
rec_type, server_encrypted_hangshake_msg = recv_tls(s)

server_finish_val_is_valid = (
    handle_encrypted_hangshake_msg(
        server_write_key, server_write_nonce_start, server_seq_num,
        server_encrypted_hangshake_msg, server_finish_val)
)
server_seq_num += 1

print("Server finish val is valid: %s" % (server_finish_val_is_valid))
print("Handshake finished")

# the rest is just for fun
print("Sending GET /")
request = b"""GET / HTTP/1.1\r\nHost: nohost\r\nConnection: close\r\n\r\n"""

encrypted_msg = gen_encrypted_appdata_msg(client_write_key, client_write_nonce_start,
                                          client_seq_num, request)
send_tls(s, APPLICATION_DATA, encrypted_msg)
client_seq_num += 1

print("Receiving an answer")

while True:
    try:
        rec_type, server_encrypted_msg = recv_tls(s)
    except BrokenPipeError:
        print("Connection closed on TCP level")
        break

    if rec_type == APPLICATION_DATA:
        msg = handle_encrypted_appdata_msg(server_write_key, server_write_nonce_start,
                                           server_seq_num, server_encrypted_msg)
        server_seq_num += 1
        print("Got: %s" % msg)
    elif rec_type == ALERT:
        alert_level, alert_description = (
            handle_encrypted_alert(server_write_key, server_write_nonce_start,
                                   server_seq_num, server_encrypted_msg)
        )
        server_seq_num += 1

        print("Got alert level: %x, description: %x" % (alert_level, alert_description))
        if alert_description == "\x00":
            print("Server sent close_notify, no waiting for more data")
            break
    else:
        print("Got msg with unknown rec_type")
