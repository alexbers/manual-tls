from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA1, SHA256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

import tinyec.ec as ec
import tinyec.registry as reg

import hashlib
import hmac
import socket
import sys

# for now no hosts support diffie hellman key exchange over tls 1.3, will fix soon
HOST = "github.com"
PORT = 443

TIMEOUT = 10

# tls 1.2 for legacy reasons, tls 1.3 will be send in extensions as required
LEGACY_TLS_VERSION = b"\x03\x03"

TLS_AES_128_GCM_SHA256 = b"\x13\x01"

CHANGE_CIPHER = b"\x14"
ALERT = b"\x15"
HANDSHAKE = b"\x16"
APPLICATION_DATA = b"\x17"


# CYPHER INFO HELPERS
def get_key_len(algo):
    keylens = {TLS_AES_128_GCM_SHA256: 16}
    return keylens[algo]


def get_iv_len(algo):
    ivlens = {TLS_AES_128_GCM_SHA256: 4}
    return ivlens[algo]


# BYTE MANIPULATION HELPERS
def bytes_to_num(b):
    return int.from_bytes(b, "big")


def num_to_bytes(num, bytes_len=None):
    assert num >= 0
    if bytes_len is None:
        bytes_len = (num.bit_length() + 7) // 8
    return int.to_bytes(num, bytes_len, "big")


def xor(a, b):
    ans = bytearray()
    for i in range(len(a)):
        ans.append(a[i] ^ b[i])
    return bytes(ans)


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

    tls_version = recv_num_bytes(s, 2)
    assert tls_version == LEGACY_TLS_VERSION

    rec_len = bytes_to_num(recv_num_bytes(s, 2))
    rec = recv_num_bytes(s, rec_len)

    return rec_type, rec


def send_tls(s, rec_type, msg):
    tls_record = rec_type + LEGACY_TLS_VERSION + num_to_bytes(len(msg), 2) + msg
    s.sendall(tls_record)


# MESSAGE AUTENTICATION CODES AND HASHING HELPERS
def hkdf_extract(data, key):
    hmac_digest = hmac.new(key, data, hashlib.sha256).digest()
    return bytes(hmac_digest)


def hkdf_expand(data, key, hash_len):
    sha256_result = bytearray()

    i = 1
    while len(sha256_result) < hash_len:
        sha256_result += hmac.new(key, sha256_result[-32:] + data + num_to_bytes(i, 1), hashlib.sha256).digest()
        i += 1
    sha256_result = sha256_result[:hash_len]

    return bytes(sha256_result)


def derive_secret(label, data, key, hash_len):
    full_label = b"tls13 " + label
    packed_data = (num_to_bytes(hash_len, 2) + num_to_bytes(len(full_label), 1) +
                   full_label + num_to_bytes(len(data), 1) + data)

    secret = hkdf_expand(data=packed_data, key=key, hash_len=hash_len)
    return secret


def do_authenticated_encryption(key, nonce_base, seq_num, msg_type, payload):
    TAG_LEN = 16
    nonce = xor(nonce_base, num_to_bytes(seq_num, 12))

    payload = payload + msg_type
    data = APPLICATION_DATA + LEGACY_TLS_VERSION + num_to_bytes(len(payload)+TAG_LEN, 2)

    encrypted_msg = AESGCM(key).encrypt(nonce, payload, associated_data=data)
    return encrypted_msg


def do_authenticated_decryption(key, nonce_start, seq_num, msg_type, payload):
    nonce = xor(nonce_start, num_to_bytes(seq_num, 12))

    # print("decrypted", AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt(payload).hex())
    data = msg_type + LEGACY_TLS_VERSION + num_to_bytes(len(payload), 2)
    msg = AESGCM(key).decrypt(nonce, payload, associated_data=data)
    msg_type, msg_data = msg[-1:], msg[:-1]
    return msg_type, msg_data


def decrypt_msg(server_write_key, server_write_nonce, seq_num, encrypted_msg):
    msg_type, msg_data = do_authenticated_decryption(server_write_key, server_write_nonce,
                                                     seq_num, APPLICATION_DATA, encrypted_msg)
    return msg_type, msg_data


def recv_tls_and_decrypt(s, key, nonce, seq_num, rec_type=APPLICATION_DATA, enc_rec_type=HANDSHAKE):
    got_rec_type, encrypted_msg = recv_tls(s)
    assert got_rec_type == rec_type

    got_enc_rec_type, msg = decrypt_msg(key, nonce, seq_num, encrypted_msg)
    assert got_enc_rec_type == enc_rec_type

    return msg


# PACKET GENERATORS AND HANDLERS
def gen_client_hello(client_random, private_ec_key):
    CLIENT_HELLO = b"\x01"

    client_version = LEGACY_TLS_VERSION  # tls 1.0, compat with old implementations

    session_id_len = b"\x00"
    session_id = b""

    cipher_suites_len = num_to_bytes(2, 2)  # only TLS_AES_128_GCM_SHA256

    compression_method_len = b"\x01"
    compression_method = b"\x00"  # no compression

    supported_versions = b"\x00\x2b"
    supported_versions_length = b"\x00\x03"
    another_supported_versions_length = b"\x02"
    tls1_3_version = b"\x03\x04"

    signature_algos = b"\x00\x0d"
    signature_algos_length = b"\x00\x04"
    another_signature_algos_length = b"\x00\x02"
    rsa_pkcs1_sha256_algo = b"\x04\x01"
    rsa_pss_rsae_sha256_algo = b"\x08\x04"
    # rsa_pkcs1_sha256_algo = b"\x04\x01"

    supported_groups = b"\x00\x0a"
    supported_groups_length = b"\x00\x04"
    another_supported_groups_length = b"\x00\x02"
    # x25519_group = b"\x00\x1d"
    secp256r1_group = b"\x00\x17"

    key_share = b"\x00\x33"
    key_share_length = num_to_bytes(len(private_ec_key) + 4 + 2, 2)
    another_key_share_length = num_to_bytes(len(private_ec_key) + 4, 2)
    # x25519_group = b"\x01\x00"
    key_exchange_len = num_to_bytes(len(private_ec_key), 2)
    key_exchange = private_ec_key

    extensions = (supported_versions + supported_versions_length +
                  another_supported_versions_length + tls1_3_version +
                  signature_algos + signature_algos_length + another_signature_algos_length +
                  rsa_pss_rsae_sha256_algo +
                  supported_groups + supported_groups_length + another_supported_groups_length +
                  secp256r1_group +
                  key_share + key_share_length + another_key_share_length +
                  secp256r1_group + key_exchange_len + key_exchange)

    client_hello_data = (client_version + client_random +
                         session_id_len + session_id + cipher_suites_len +
                         TLS_AES_128_GCM_SHA256 +
                         compression_method_len + compression_method +
                         num_to_bytes(len(extensions), 2)) + extensions

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

    extensions_length = bytes_to_num(server_hello[39 + session_id_len + 3: 39 + session_id_len + 3 + 2])
    extensions = server_hello[39 + session_id_len + 3 + 2: 39 + session_id_len + 3 + 2 + extensions_length]

    public_ec_key = b""
    ptr = 0
    while ptr < extensions_length:
        extension_type = extensions[ptr: ptr + 2]
        extension_length = bytes_to_num(extensions[ptr+2: ptr + 4])
        print("extension_length", extension_length)
        KEY_SHARE = b"\x00\x33"
        if extension_type != KEY_SHARE:
            ptr += extension_length + 4
            continue
        group = extensions[ptr+4: ptr+6]
        # x25519_group = b"\x00\x1d"
        secp256r1_group = b"\x00\x17"
        assert group == secp256r1_group
        key_exchange_len = bytes_to_num(extensions[ptr+6: ptr+8])

        public_ec_key = extensions[ptr+8:ptr+8+key_exchange_len]
        break

    return server_random, session_id, public_ec_key


def handle_encrypted_extensions(msg):
    ENCRYPTED_EXTENSIONS = 0x8

    assert msg[0] == ENCRYPTED_EXTENSIONS
    extensions_length = bytes_to_num(msg[1:4])
    assert len(msg[4:]) >= extensions_length
    # ignore the rest


def handle_server_cert(server_cert_data):
    handshake_type = server_cert_data[0]

    CERTIFICATE = 0x0b
    assert handshake_type == CERTIFICATE

    certificate_field_len = bytes_to_num(server_cert_data[1:4])

    certificates = []

    cert_string_left = server_cert_data[4: 4 + certificate_field_len]
    while cert_string_left:
        cert_type = cert_string_left[0]
        cert_entry_len = bytes_to_num(cert_string_left[1:4])

        cert_len = bytes_to_num(cert_string_left[4:7])

        certificates.append(cert_string_left[7: 7 + cert_len])
        cert_string_left = cert_string_left[4 + cert_entry_len:]

    return certificates


def handle_cert_verify(cert_verify_data, rsa, msgs_so_far):
    handshake_type = cert_verify_data[0]

    CERTIFICATE_VERIFY = 0x0f
    assert handshake_type == CERTIFICATE_VERIFY

    cert_verify_len = bytes_to_num(cert_verify_data[1:4])
    assert len(cert_verify_data[4:]) >= cert_verify_len

    cert_verify_method = cert_verify_data[4:6]
    signature_len = bytes_to_num(cert_verify_data[6:8])
    signature = cert_verify_data[8: 8+signature_len]

    message = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + hashlib.sha256(msgs_so_far).digest()

    try:
        pss.new(rsa).verify(SHA256.new(message), signature)
    except ValueError:
        print("Warning: Certificate signature is wrong!")


def handle_finished(finished_data, server_finished_key, msgs_so_far):
    handshake_type = finished_data[0]

    FINISHED = 0x14
    assert handshake_type == FINISHED

    verify_data_len = bytes_to_num(finished_data[1:4])
    verify_data = finished_data[4:4+verify_data_len]

    msgs_digest = hashlib.sha256(msgs_so_far).digest()
    hmac_digest = hmac.new(server_finished_key, msgs_digest, hashlib.sha256).digest()

    return verify_data == hmac_digest


def gen_change_cipher():
    CHANGE_CIPHER_SPEC_MSG = b"\x01"
    return CHANGE_CIPHER_SPEC_MSG


def gen_encrypted_finished(client_write_key, client_write_iv, client_seq_num, client_finish_val):
    FINISHED = b"\x14"

    msg = FINISHED + num_to_bytes(len(client_finish_val), 3) + client_finish_val

    return do_authenticated_encryption(client_write_key, client_write_iv, client_seq_num,
                                       HANDSHAKE, msg)


print("Connecting to %s:%d" % (HOST, PORT))
s = socket.create_connection((HOST, PORT), TIMEOUT)

print("Handshake: sending a client hello")
client_random = b"\xAB" * 32
print("Client random: %s" % client_random.hex())


curve = reg.get_curve("secp256r1")

our_ecdh_privkey = 1234
our_ecdh_pubkey = our_ecdh_privkey * curve.g

private_ec_key = b"\x04" + num_to_bytes(our_ecdh_pubkey.x, 32) + num_to_bytes(our_ecdh_pubkey.y, 32)

client_hello = gen_client_hello(client_random, private_ec_key)
send_tls(s, HANDSHAKE, client_hello)

###########################
print("Handshake: receiving a server hello")
rec_type, server_hello = recv_tls(s)

if rec_type == ALERT:
    print("Server sent us ALERT, it probably doesn't support " +
          "TLS_AES_128_GCM_SHA256 algo")
    sys.exit(1)

assert rec_type == HANDSHAKE

server_random, session_id, public_ec_key = handle_server_hello(server_hello)
print("Server random: %s" % server_random.hex())
print("Session id: %s" % session_id.hex())
print("Server ECDH pubkey: %s" % public_ec_key.hex())

server_ecdh_pubkey = ec.Point(curve, bytes_to_num(public_ec_key[1:33]), bytes_to_num(public_ec_key[33:]))

our_secret_point = our_ecdh_privkey * server_ecdh_pubkey
our_secret = num_to_bytes(our_secret_point.x, 32)

print("Our common DH secret (premaster secret) is: %s" % our_secret.hex())

###########################
print("Handshake: receiving a change cipher msg")
rec_type, server_change_cipher = recv_tls(s)
assert rec_type == CHANGE_CIPHER

# the sha256 from empty msg is used
derive_start_hash = hashlib.sha256(b"").digest()
early_secret = hkdf_extract(data=b"\x00" * 32, key=b"")
preextractsec = derive_secret(b"derived", data=derive_start_hash, key=early_secret, hash_len=32)
handshake_secret = hkdf_extract(data=our_secret, key=preextractsec)
hello_hash = hashlib.sha256(client_hello + server_hello).digest()
server_hs_secret = derive_secret(b"s hs traffic", data=hello_hash, key=handshake_secret, hash_len=32)
server_write_key = derive_secret(b"key", data=b"", key=server_hs_secret, hash_len=16)
server_write_iv = derive_secret(b"iv", data=b"", key=server_hs_secret, hash_len=12)
server_finished_key = derive_secret(b"finished", data=b"", key=server_hs_secret, hash_len=32)
client_hs_secret = derive_secret(b"c hs traffic", data=hello_hash, key=handshake_secret, hash_len=32)
client_write_key = derive_secret(b"key", data=b"", key=client_hs_secret, hash_len=16)
client_write_iv = derive_secret(b"iv", data=b"", key=client_hs_secret, hash_len=12)
client_finished_key = derive_secret(b"finished", data=b"", key=client_hs_secret, hash_len=32)

print("preextractsec", preextractsec.hex())
print("handshake_secret", handshake_secret.hex())
print("hello_hash", hello_hash.hex())
print("server_hs_secret", server_hs_secret.hex())
print("server_write_key", server_write_key.hex())
print("server_write_iv", server_write_iv.hex())
print("server_finished_key", server_finished_key.hex())
print("client_hs_secret", client_hs_secret.hex())
print("client_write_key", client_write_key.hex())
print("client_write_iv", client_write_iv.hex())
print("client_finished_key", client_finished_key.hex())


client_seq_num = 0  # for use in authenticated encryption
server_seq_num = 0

###########################
encrypted_extensions = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
server_seq_num += 1

print("encrypted_extensions", encrypted_extensions.hex())
handle_encrypted_extensions(encrypted_extensions)

###########################
server_cert = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
server_seq_num += 1

certs = handle_server_cert(server_cert)
print("Got %d certs" % len(certs))

rsa = RSA.import_key(certs[0])

###########################
cert_verify = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
server_seq_num += 1

msgs_so_far = client_hello + server_hello + encrypted_extensions + server_cert
handle_cert_verify(cert_verify, rsa, msgs_so_far)

###########################
finished = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
server_seq_num += 1

msgs_so_far = msgs_so_far + cert_verify + finished
srv_finish_ok = handle_finished(finished, server_finished_key, msgs_so_far)
if srv_finish_ok:
    print("Server sent valid finish handshake msg")
else:
    print("Warning: Server sent wrong handshake finished msg")

###########################
print("Handshake: sending a change cipher msg")
change_cipher = gen_change_cipher()
send_tls(s, CHANGE_CIPHER, change_cipher)

###########################
# All client messages beyond this point are encrypted

msgs_sha256 = hashlib.sha256(msgs_so_far).digest()
client_finish_val = hmac.new(client_finished_key, msgs_sha256, hashlib.sha256).digest()
print("client_finish_val", client_finish_val.hex())

print("Handshake: sending an encrypted finished msg")
encrypted_hangshake_msg = gen_encrypted_finished(client_write_key, client_write_iv, client_seq_num,
                                                 client_finish_val)
send_tls(s, APPLICATION_DATA, encrypted_hangshake_msg)
client_seq_num += 1

print("encrypted_hangshake_msg", encrypted_hangshake_msg.hex())
print("Handshake finished")

###########################
msgs_so_far_hash = hashlib.sha256(msgs_so_far).digest()

# rederive application secrets
premaster_secret = derive_secret(b"derived", data=derive_start_hash, key=handshake_secret, hash_len=32)
master_secret = hkdf_extract(data=b"\x00" * 32, key=premaster_secret)
server_secret = derive_secret(b"s ap traffic", data=msgs_so_far_hash, key=master_secret, hash_len=32)
server_write_key = derive_secret(b"key", data=b"", key=server_secret, hash_len=16)
server_write_iv = derive_secret(b"iv", data=b"", key=server_secret, hash_len=12)
client_secret = derive_secret(b"c ap traffic", data=msgs_so_far_hash, key=master_secret, hash_len=32)
client_write_key = derive_secret(b"key", data=b"", key=client_secret, hash_len=16)
client_write_iv = derive_secret(b"iv", data=b"", key=client_secret, hash_len=12)

print("After secrets regeneration")
print("premaster_secret", premaster_secret.hex())
print("master_secret", master_secret.hex())
print("server_secret", server_secret.hex())
print("server_write_key", server_write_key.hex())
print("server_write_iv", server_write_iv.hex())
print("client_secret", client_secret.hex())
print("client_write_key", client_write_key.hex())
print("client_write_iv", client_write_iv.hex())

client_seq_num = 0
server_seq_num = 0

###########################
new_session_ticket = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
print("new_session_ticket", new_session_ticket.hex())
server_seq_num += 1

###########################
new_session_ticket = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
print("new_session_ticket", new_session_ticket.hex())
server_seq_num += 1

###########################
# the rest is just for fun
request = b"""GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"""
print("Sending", request)

encrypted_msg = do_authenticated_encryption(client_write_key, client_write_iv,
                                            client_seq_num, APPLICATION_DATA, request)
send_tls(s, APPLICATION_DATA, encrypted_msg)
client_seq_num += 1

###########################
print("Receiving an answer")

while True:
    try:
        rec_type, server_encrypted_msg = recv_tls(s)
    except BrokenPipeError:
        print("Connection closed on TCP level")
        break

    if rec_type == APPLICATION_DATA:
        msg_type, msg = decrypt_msg(server_write_key, server_write_iv,
                                    server_seq_num, server_encrypted_msg)
        server_seq_num += 1
        if msg_type == APPLICATION_DATA:
            print("Got: %s" % msg.decode(errors="ignore"))
        elif msg_type == ALERT:
            alert_level, alert_description = msg

            print("Got alert level: %x, description: %x" % (alert_level, alert_description))
            if alert_description == 0:
                print("Server sent close_notify, no waiting for more data")
                break
    else:
        print("Got msg with unknown rec_type")
