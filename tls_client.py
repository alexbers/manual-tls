import socket

HOST = "habr.com"
PORT = 443
TIMEOUT = 10

REQUEST = b"HEAD /ru/company/habr/blog/522330/ HTTP/1.1\r\nHost: habr.com\r\nConnection: close\r\n\r\n"

# in tls 1.3 the version tls 1.2 is sent for better compatibility
LEGACY_TLS_VERSION = b"\x03\x03"
TLS_AES_128_GCM_SHA256 = b"\x13\x01"

CHANGE_CIPHER = b"\x14"
ALERT = b"\x15"
HANDSHAKE = b"\x16"
APPLICATION_DATA = b"\x17"


# BYTE MANIPULATION HELPERS
def bytes_to_num(b):
    return int.from_bytes(b, "big")


def num_to_bytes(num, bytes_len):
    return int.to_bytes(num, bytes_len, "big")


def rotr(num, count):
    return num >> count | num << (32 - count)


def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


# SYMMETRIC CIPHERS
# AES_SBOX is some permutation of numbers 0-255
AES_SBOX = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125,
    250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
    52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235,
    39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
    0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51,
    133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33,
    16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96,
    129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36,
    92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
    234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139,
    138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17,
    105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104,
    65, 153, 45, 15, 176, 84, 187, 22
]

AES_ROUNDS = 10


def aes128_expand_key(key):
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    enc_keys = [[0, 0, 0, 0] for i in range(AES_ROUNDS + 1)]
    enc_keys[0] = [bytes_to_num(key[i:i + 4]) for i in [0, 4, 8, 12]]

    for t in range(1, AES_ROUNDS + 1):
        prev_key = enc_keys[t-1]
        enc_keys[t][0] = ((AES_SBOX[(prev_key[3] >> 8*2) & 0xFF] << 8*3) ^
                          (AES_SBOX[(prev_key[3] >> 8*1) & 0xFF] << 8*2) ^
                          (AES_SBOX[(prev_key[3] >> 8*0) & 0xFF] << 8*1) ^
                          (AES_SBOX[(prev_key[3] >> 8*3) & 0xFF] << 8*0) ^
                          (RCON[t-1] << 8*3) ^ prev_key[0])

        for i in range(1, 4):
            enc_keys[t][i] = enc_keys[t][i-1] ^ prev_key[i]
    return enc_keys


def aes128_encrypt(key, plaintext):
    TWOTIMES = [2*num if 2*num < 256 else 2*num & 0xff ^ 27 for num in range(256)]

    enc_keys = aes128_expand_key(key)

    t = [bytes_to_num(plaintext[4*i:4*i + 4]) ^ enc_keys[0][i] for i in range(4)]
    for r in range(1, AES_ROUNDS):
        t = [[AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF],
              AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF],
              AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF],
              AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF]] for i in range(4)]

        t = [[c[1] ^ c[2] ^ c[3] ^ TWOTIMES[c[0] ^ c[1]],
              c[0] ^ c[2] ^ c[3] ^ TWOTIMES[c[1] ^ c[2]],
              c[0] ^ c[1] ^ c[3] ^ TWOTIMES[c[2] ^ c[3]],
              c[0] ^ c[1] ^ c[2] ^ TWOTIMES[c[3] ^ c[0]]] for c in t]

        t = [bytes_to_num(t[i]) ^ enc_keys[r][i] for i in range(4)]

    result = [bytes([
        AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF] ^ (enc_keys[-1][i] >> 8*3) & 0xFF,
        AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF] ^ (enc_keys[-1][i] >> 8*2) & 0xFF,
        AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF] ^ (enc_keys[-1][i] >> 8*1) & 0xFF,
        AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF] ^ (enc_keys[-1][i] >> 8*0) & 0xFF
    ]) for i in range(4)]
    return b"".join(result)


def aes128_ctr_encrypt(key, msg, nonce, counter_start_val):
    BLOCK_SIZE = 16

    ans = []
    counter = counter_start_val
    for s in range(0, len(msg), BLOCK_SIZE):
        chunk = msg[s:s+BLOCK_SIZE]

        chunk_nonce = nonce + num_to_bytes(counter, 4)
        encrypted_chunk_nonce = aes128_encrypt(key, chunk_nonce)

        decrypted_chunk = xor(chunk, encrypted_chunk_nonce)
        ans.append(decrypted_chunk)

        counter += 1
    return b"".join(ans)


def aes128_ctr_decrypt(key, msg, nonce, counter_start_val):
    return aes128_ctr_encrypt(key, msg, nonce, counter_start_val)


def mutliply_blocks(x, y):
    z = 0
    for i in range(128):
        if x & (1 << (127 - i)):
            z ^= y
        if y & 1:
            y = (y >> 1) ^ (0xe1 << 120)
        else:
            y = y >> 1
    return z


def ghash(h, data):
    BLOCK_SIZE = 16

    y = 0
    for pos in range(0, len(data), BLOCK_SIZE):
        chunk = bytes_to_num(data[pos: pos + BLOCK_SIZE])
        y = mutliply_blocks(y ^ chunk, h)
    return y


def calc_pretag(key, encrypted_msg, associated_data):
    v = b"\x00" * (16 * ((len(associated_data) + 15) // 16) - len(associated_data))
    u = b"\x00" * (16 * ((len(encrypted_msg) + 15) // 16) - len(encrypted_msg))

    h = bytes_to_num(aes128_encrypt(key, b"\x00" * 16))
    data = (associated_data + v + encrypted_msg + u +
            num_to_bytes(len(associated_data)*8, 8) + num_to_bytes(len(encrypted_msg)*8, 8))
    return num_to_bytes(ghash(h, data), 16)


def aes128_gcm_decrypt(key, msg, nonce, associated_data):
    TAG_LEN = 16

    encrypted_msg, tag = msg[:-TAG_LEN], msg[-TAG_LEN:]

    pretag = calc_pretag(key, encrypted_msg, associated_data)
    check_tag = aes128_ctr_encrypt(key, pretag, nonce, counter_start_val=1)
    if check_tag != tag:
        raise ValueError("Decrypt error, bad tag")
    return aes128_ctr_decrypt(key, encrypted_msg, nonce, counter_start_val=2)


def aes128_gcm_encrypt(key, msg, nonce, associated_data):
    encrypted_msg = aes128_ctr_encrypt(key, msg, nonce, counter_start_val=2)

    pretag = calc_pretag(key, encrypted_msg, associated_data)
    tag = aes128_ctr_encrypt(key, pretag, nonce, counter_start_val=1)
    return encrypted_msg + tag


# CRYPTOGRAPHIC HASH FUNCTIONS AND MESSAGE AUTHENTICATION CODES
SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def sha256(msg):
    msg += b"\x80" + b"\x00" * ((64-(len(msg) + 1 + 8)) % 64) + num_to_bytes(len(msg)*8, 8)

    ss = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for pos in range(0, len(msg), 64):
        chunk = msg[pos:pos + 64]

        w = [bytes_to_num(chunk[4*i:4*i+4]) for i in range(16)]
        for i in range(16, 64):
            a = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            b = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((a + b + w[i-16] + w[i-7]) & 0xffffffff)

        s = ss.copy()
        for i in range(64):
            c = (s[4] & s[5]) ^ ((s[4] ^ 0xffffffff) & s[6])
            t = SHA256_K[i] + s[7] + c + w[i] + (rotr(s[4], 6) ^ rotr(s[4], 11) ^ rotr(s[4], 25))
            q = rotr(s[0], 2) ^ rotr(s[0], 13) ^ rotr(s[0], 22)
            m = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2])
            s = [(q + m + t) & 0xffffffff, s[0], s[1], s[2], (s[3] + t) & 0xffffffff, s[4], s[5], s[6]]

        ss = [(ss[i] + s[i]) & 0xffffffff for i in range(8)]
    return b"".join(num_to_bytes(a, 4) for a in ss)


def hmac_sha256(key, data):
    BLOCK_SIZE = 512 // 8
    IPAD = b"\x36" * BLOCK_SIZE
    OPAD = b"\x5c" * BLOCK_SIZE

    if len(key) <= BLOCK_SIZE:
        key += b"\x00" * (BLOCK_SIZE - len(key))
    else:
        key = sha256(key)
    return sha256(xor(key, OPAD) + sha256(xor(key, IPAD) + data))


def derive_secret(label, key, data, hash_len):
    full_label = b"tls13 " + label
    packed_data = (num_to_bytes(hash_len, 2) + num_to_bytes(len(full_label), 1) +
                   full_label + num_to_bytes(len(data), 1) + data)

    secret = bytearray()
    i = 1
    while len(secret) < hash_len:
        secret += hmac_sha256(key, secret[-32:] + packed_data + num_to_bytes(i, 1))
        i += 1
    return bytes(secret[:hash_len])


# ELLIPTIC CURVE FUNCTIONS
def egcd(a, b):
    if a == 0:
        return 0, 1
    y, x = egcd(b % a, a)
    return x - (b // a) * y, y


def mod_inv(a, p):
    if a < 0:
        return p - egcd(-a, p)[0]
    return egcd(a, p)[0]


def add_two_ec_points(p1_x, p1_y, p2_x, p2_y, a, p):
    if p1_x == p2_x and p1_y == p2_y:
        s = (3*p1_x*p1_x + a) * mod_inv(2*p2_y, p)
    elif p1_x != p2_x:
        s = (p1_y - p2_y) * mod_inv(p1_x - p2_x, p)
    else:
        raise NotImplementedError

    x = s*s - p1_x - p2_x
    y = -p1_y + s*(p1_x - x)
    return x % p, y % p


def multiply_num_on_ec_point(num, g_x, g_y, a, p):
    x, y = None, None
    while num:
        if num & 1:
            x, y = add_two_ec_points(x, y, g_x, g_y, a, p) if x else (g_x, g_y)
        g_x, g_y = add_two_ec_points(g_x, g_y, g_x, g_y, a, p)
        num >>= 1
    return x, y


# AUTHENTIATED ENCRYPTION HELPERS
def do_authenticated_encryption(key, nonce_base, seq_num, msg_type, payload):
    TAG_LEN = 16

    payload += msg_type
    nonce = xor(nonce_base, num_to_bytes(seq_num, 12))
    data = APPLICATION_DATA + LEGACY_TLS_VERSION + num_to_bytes(len(payload)+TAG_LEN, 2)

    encrypted_msg = aes128_gcm_encrypt(key, payload, nonce, associated_data=data)
    return encrypted_msg


def do_authenticated_decryption(key, nonce_start, seq_num, msg_type, payload):
    nonce = xor(nonce_start, num_to_bytes(seq_num, 12))

    data = msg_type + LEGACY_TLS_VERSION + num_to_bytes(len(payload), 2)
    msg = aes128_gcm_decrypt(key, payload, nonce, associated_data=data)

    msg_type, msg_data = msg[-1:], msg[:-1]
    return msg_type, msg_data


# NETWORK AND LOW LEVEL TLS PROTOCOL HELPERS
def recv_num_bytes(s, num):
    ret = bytearray()
    while len(ret) < num:
        data = s.recv(min(32768, num - len(ret)))
        if not data:
            raise BrokenPipeError
        ret += data
    return bytes(ret)


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


def recv_tls_and_decrypt(s, key, nonce, seq_num):
    rec_type, encrypted_msg = recv_tls(s)
    assert rec_type == APPLICATION_DATA

    msg_type, msg = do_authenticated_decryption(key, nonce, seq_num, APPLICATION_DATA, encrypted_msg)
    return msg_type, msg


# PACKET GENERATORS AND HANDLERS
def gen_client_hello(client_random, ecdh_pubkey_x, ecdh_pubkey_y):
    CLIENT_HELLO = b"\x01"

    session_id = b""
    compression_method = b"\x00"  # no compression

    supported_versions = b"\x00\x2b"
    supported_versions_length = b"\x00\x03"
    another_supported_versions_length = b"\x02"
    tls1_3_version = b"\x03\x04"
    supported_version_extension = (supported_versions + supported_versions_length +
                                   another_supported_versions_length + tls1_3_version)

    signature_algos = b"\x00\x0d"
    signature_algos_length = b"\x00\x04"
    another_signature_algos_length = b"\x00\x02"
    rsa_pss_rsae_sha256_algo = b"\x08\x04"
    signature_algos_extension = (signature_algos + signature_algos_length +
                                 another_signature_algos_length + rsa_pss_rsae_sha256_algo)

    supported_groups = b"\x00\x0a"
    supported_groups_length = b"\x00\x04"
    another_supported_groups_length = b"\x00\x02"
    secp256r1_group = b"\x00\x17"
    supported_groups_extension = (supported_groups + supported_groups_length +
                                  another_supported_groups_length + secp256r1_group)

    ecdh_pubkey = b"\x04" + num_to_bytes(ecdh_pubkey_x, 32) + num_to_bytes(ecdh_pubkey_y, 32)

    key_share = b"\x00\x33"
    key_share_length = num_to_bytes(len(ecdh_pubkey) + 4 + 2, 2)
    another_key_share_length = num_to_bytes(len(ecdh_pubkey) + 4, 2)
    key_exchange_len = num_to_bytes(len(ecdh_pubkey), 2)
    key_share_extension = (key_share + key_share_length + another_key_share_length +
                           secp256r1_group + key_exchange_len + ecdh_pubkey)

    extensions = (supported_version_extension + signature_algos_extension +
                  supported_groups_extension + key_share_extension)

    client_hello_data = (LEGACY_TLS_VERSION + client_random +
                         num_to_bytes(len(session_id), 1) + session_id +
                         num_to_bytes(len(TLS_AES_128_GCM_SHA256), 2) + TLS_AES_128_GCM_SHA256 +
                         num_to_bytes(len(compression_method), 1) + compression_method +
                         num_to_bytes(len(extensions), 2)) + extensions

    client_hello_len_bytes = num_to_bytes(len(client_hello_data), 3)
    client_hello_tlv = CLIENT_HELLO + client_hello_len_bytes + client_hello_data

    print(f"    Type is the client hello: {CLIENT_HELLO.hex()}")
    print(f"    Length is {len(client_hello_data)}: {client_hello_len_bytes.hex()}")
    print(f"    Legacy client version is TLS 1.2: {LEGACY_TLS_VERSION.hex()}")
    print(f"    Client random: {client_random.hex()}")
    print(f"    Session id len is 0: {num_to_bytes(len(session_id), 1).hex()}")
    print(f"    Session id: {session_id.hex()}")
    print(f"    Cipher suites len is 2: {num_to_bytes(len(TLS_AES_128_GCM_SHA256), 2)}")
    print(f"    Cipher suite is TLS_AES_128_GCM_SHA256: {TLS_AES_128_GCM_SHA256.hex()}")
    print(f"    Compression method len is 1: {num_to_bytes(len(compression_method), 1).hex()}")
    print(f"    Compression method is no compression: {compression_method.hex()}")
    print(f"    Extensions len is {len(extensions)}: {num_to_bytes(len(extensions), 2).hex()}")
    print(f"    Extension type is supported_versions: {supported_versions.hex()}")
    print(f"        Extension len is 3: {supported_versions_length.hex()}")
    print(f"        Extension field len is 2: {another_supported_versions_length.hex()}")
    print(f"        Version is TLS 1.3: {tls1_3_version.hex()}")
    print(f"    Extension type is signature_algos: {signature_algos.hex()}")
    print(f"        Extension len is 4: {signature_algos_length.hex()}")
    print(f"        Extension field len is 2: {another_signature_algos_length.hex()}")
    print(f"        Algo is rsa_pss_rsae_sha256_algo: {rsa_pss_rsae_sha256_algo.hex()}")
    print(f"    Extension type is supported_groups: {supported_groups.hex()}")
    print(f"        Extension len is 4: {supported_groups_length.hex()}")
    print(f"        Extension field len is 2: {another_supported_groups_length.hex()}")
    print(f"        Group is secp256r1_group: {secp256r1_group.hex()}")
    print(f"    Extension type is key_share: {key_share.hex()}")
    print(f"        Extension len is {bytes_to_num(key_share_length)}: {key_share_length.hex()}")
    print(f"        Extension field len is {bytes_to_num(another_key_share_length)}: {another_key_share_length.hex()}")
    print(f"        Key length {len(ecdh_pubkey)}: {key_exchange_len.hex()}")
    print(f"        Key is: {ecdh_pubkey.hex()}")

    return client_hello_tlv


def handle_server_hello(server_hello):
    handshake_type = server_hello[0]

    SERVER_HELLO = 0x2
    assert handshake_type == SERVER_HELLO

    server_hello_len = server_hello[1:4]
    server_version = server_hello[4:6]

    server_random = server_hello[6:38]

    session_id_len = bytes_to_num(server_hello[38:39])
    session_id = server_hello[39:39 + session_id_len]

    cipher_suite = server_hello[39 + session_id_len:39 + session_id_len + 2]
    assert cipher_suite == TLS_AES_128_GCM_SHA256

    compression_method = server_hello[39 + session_id_len + 2:39 + session_id_len + 3]

    extensions_length = bytes_to_num(server_hello[39 + session_id_len + 3:39 + session_id_len + 3 + 2])
    extensions = server_hello[39 + session_id_len + 3 + 2:39 + session_id_len + 3 + 2 + extensions_length]

    public_ec_key = b""
    ptr = 0
    while ptr < extensions_length:
        extension_type = extensions[ptr: ptr + 2]
        extension_length = bytes_to_num(extensions[ptr+2: ptr + 4])
        KEY_SHARE = b"\x00\x33"
        if extension_type != KEY_SHARE:
            ptr += extension_length + 4
            continue
        group = extensions[ptr+4: ptr+6]
        secp256r1_group = b"\x00\x17"
        assert group == secp256r1_group
        key_exchange_len = bytes_to_num(extensions[ptr+6: ptr+8])

        public_ec_key = extensions[ptr+8:ptr+8+key_exchange_len]
        break

    if not public_ec_key:
        raise ValueError("No public ECDH key in server hello")

    public_ec_key_x = bytes_to_num(public_ec_key[1:33])
    public_ec_key_y = bytes_to_num(public_ec_key[33:])

    print(f"    Type is the server hello: {server_hello[:1].hex()}")
    print(f"    Length is {bytes_to_num(server_hello_len)}: {server_hello_len.hex()}")
    print(f"    Legacy server version is TLS 1.2: {server_version.hex()}")
    print(f"    Server random: {server_random.hex()}")
    print(f"    Session id len is {session_id_len}: {server_hello[38:39].hex()}")
    print(f"    Session id: {session_id.hex()}")
    print(f"    Cipher suite is TLS_AES_128_GCM_SHA256: {cipher_suite.hex()}")
    print(f"    Compression method is no compression: {compression_method.hex()}")
    print(f"    Extensions len is {extensions_length}: {num_to_bytes(extensions_length, 2).hex()}")
    print(f"    Extension parsing was skipped, but public_ec_key is {public_ec_key.hex()}")

    return server_random, session_id, public_ec_key_x, public_ec_key_y


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

    message = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + sha256(msgs_so_far)

    # try:
    #     pss.new(rsa).verify(SHA256.new(message), signature)
    # except ValueError:
    #     return False
    return True


def handle_finished(finished_data, server_finished_key, msgs_so_far):
    handshake_type = finished_data[0]

    FINISHED = 0x14
    assert handshake_type == FINISHED

    verify_data_len = bytes_to_num(finished_data[1:4])
    verify_data = finished_data[4:4+verify_data_len]

    hmac_digest = hmac_sha256(server_finished_key, sha256(msgs_so_far))
    return verify_data == hmac_digest


def gen_change_cipher():
    CHANGE_CIPHER_SPEC_MSG = b"\x01"
    return CHANGE_CIPHER_SPEC_MSG


def gen_encrypted_finished(client_write_key, client_write_iv, client_seq_num, client_finish_val):
    FINISHED = b"\x14"
    msg = FINISHED + num_to_bytes(len(client_finish_val), 3) + client_finish_val

    return do_authenticated_encryption(client_write_key, client_write_iv, client_seq_num,
                                       HANDSHAKE, msg)


print(f"Connecting to {HOST}:{PORT}")
s = socket.create_connection((HOST, PORT), TIMEOUT)

print("Generating params for a client hello, the first message of TLS handshake")
SECP256R1_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
SECP256R1_A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
SECP256R1_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
               0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

client_random = b"\xAB" * 32
our_ecdh_privkey = 42
our_ecdh_pubkey_x, our_ecdh_pubkey_y = (
    multiply_num_on_ec_point(our_ecdh_privkey, SECP256R1_G[0], SECP256R1_G[1], SECP256R1_A, SECP256R1_P)
)

print(f"    Client random: {client_random.hex()}")
print(f"    Our ECDH (Elliptic-curve Diffie-Hellman) private key: {our_ecdh_privkey}")
print(f"    Our ECDH public key: x={our_ecdh_pubkey_x} y={our_ecdh_pubkey_y}")

print("Generating the client hello")
client_hello = gen_client_hello(client_random, our_ecdh_pubkey_x, our_ecdh_pubkey_y)

print("Sending the client hello")
send_tls(s, HANDSHAKE, client_hello)

###########################
print("Receiving a server hello")
rec_type, server_hello = recv_tls(s)

if rec_type == ALERT:
    print("Server sent us ALERT, it probably doesn't support TLS_AES_128_GCM_SHA256 algo")
    exit(1)

assert rec_type == HANDSHAKE

server_random, session_id, server_ecdh_pubkey_x, server_ecdh_pubkey_y = handle_server_hello(server_hello)
print(f"    Server ECDH public key: x={server_ecdh_pubkey_x} y={server_ecdh_pubkey_y}")

###########################
print("Receiving a change cipher msg, all communication will be encrypted")
rec_type, server_change_cipher = recv_tls(s)
assert rec_type == CHANGE_CIPHER

our_secret_point_x = multiply_num_on_ec_point(our_ecdh_privkey, server_ecdh_pubkey_x, server_ecdh_pubkey_y,
                                              SECP256R1_A, SECP256R1_P)[0]
our_secret = num_to_bytes(our_secret_point_x, 32)
print(f"    Our common ECDH secret is: {our_secret.hex()}, deriving keys")

early_secret = hmac_sha256(key=b"", data=b"\x00" * 32)
preextractsec = derive_secret(b"derived", key=early_secret, data=sha256(b""), hash_len=32)
handshake_secret = hmac_sha256(key=preextractsec, data=our_secret)
hello_hash = sha256(client_hello + server_hello)
server_hs_secret = derive_secret(b"s hs traffic", key=handshake_secret, data=hello_hash, hash_len=32)
server_write_key = derive_secret(b"key", key=server_hs_secret, data=b"", hash_len=16)
server_write_iv = derive_secret(b"iv", key=server_hs_secret, data=b"", hash_len=12)
server_finished_key = derive_secret(b"finished", key=server_hs_secret, data=b"", hash_len=32)
client_hs_secret = derive_secret(b"c hs traffic", key=handshake_secret, data=hello_hash, hash_len=32)
client_write_key = derive_secret(b"key", key=client_hs_secret, data=b"", hash_len=16)
client_write_iv = derive_secret(b"iv", key=client_hs_secret, data=b"", hash_len=12)
client_finished_key = derive_secret(b"finished", key=client_hs_secret, data=b"", hash_len=32)

print("    handshake_secret", handshake_secret.hex())
print("    server_write_key", server_write_key.hex())
print("    server_write_iv", server_write_iv.hex())
print("    server_finished_key", server_finished_key.hex())
print("    client_write_key", client_write_key.hex())
print("    client_write_iv", client_write_iv.hex())
print("    client_finished_key", client_finished_key.hex())

client_seq_num = 0  # for use in authenticated encryption
server_seq_num = 0

###########################
print("Receiving encrypted extensions")
rec_type, encrypted_extensions = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
assert rec_type == HANDSHAKE
server_seq_num += 1

print(f"    Encrypted_extensions: {encrypted_extensions.hex()}, parsing skipped")
handle_encrypted_extensions(encrypted_extensions)

###########################
print("Receiving server certificates")
rec_type, server_cert = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
assert rec_type == HANDSHAKE
server_seq_num += 1

certs = handle_server_cert(server_cert)
print("    Got %d certs" % len(certs))

###########################
print("Receiving server verify certificate")
rec_type, cert_verify = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
assert rec_type == HANDSHAKE
server_seq_num += 1

msgs_so_far = client_hello + server_hello + encrypted_extensions + server_cert
cert_ok = handle_cert_verify(cert_verify, None, msgs_so_far)
print("    Certificate verifying skipped")

###########################
print("Receiving server finished")
rec_type, finished = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
assert rec_type == HANDSHAKE
server_seq_num += 1

msgs_so_far = msgs_so_far + cert_verify
srv_finish_ok = handle_finished(finished, server_finished_key, msgs_so_far)
if not srv_finish_ok:
    print("    Server sent valid finish handshake msg")
else:
    print("    Warning: Server sent wrong handshake finished msg")

###########################
print("Handshake: sending a change cipher msg")
change_cipher = gen_change_cipher()
send_tls(s, CHANGE_CIPHER, change_cipher)

###########################
# All client messages beyond this point are encrypted
msgs_so_far = msgs_so_far + finished
msgs_sha256 = sha256(msgs_so_far)
client_finish_val = hmac_sha256(client_finished_key, msgs_sha256)

print("Handshake: sending an encrypted finished msg")
encrypted_hangshake_msg = gen_encrypted_finished(client_write_key, client_write_iv, client_seq_num,
                                                 client_finish_val)
print(f"    Client finish value {client_finish_val.hex()}")
send_tls(s, APPLICATION_DATA, encrypted_hangshake_msg)
client_seq_num += 1

print("Handshake finished, regenerating secrets for application data")

###########################
# rederive application secrets
msgs_so_far_hash = sha256(msgs_so_far)
premaster_secret = derive_secret(b"derived", data=sha256(b""), key=handshake_secret, hash_len=32)
master_secret = hmac_sha256(key=premaster_secret, data=b"\x00" * 32)
server_secret = derive_secret(b"s ap traffic", data=msgs_so_far_hash, key=master_secret, hash_len=32)
server_write_key = derive_secret(b"key", data=b"", key=server_secret, hash_len=16)
server_write_iv = derive_secret(b"iv", data=b"", key=server_secret, hash_len=12)
client_secret = derive_secret(b"c ap traffic", data=msgs_so_far_hash, key=master_secret, hash_len=32)
client_write_key = derive_secret(b"key", data=b"", key=client_secret, hash_len=16)
client_write_iv = derive_secret(b"iv", data=b"", key=client_secret, hash_len=12)

print("    premaster_secret", premaster_secret.hex())
print("    master_secret", master_secret.hex())
print("    server_secret", server_secret.hex())
print("    server_write_key", server_write_key.hex())
print("    server_write_iv", server_write_iv.hex())
print("    client_secret", client_secret.hex())
print("    client_write_key", client_write_key.hex())
print("    client_write_iv", client_write_iv.hex())

# reset sequence numbers
client_seq_num = 0
server_seq_num = 0

###########################
# the rest is just for fun
print(f"Sending {REQUEST}")

encrypted_msg = do_authenticated_encryption(client_write_key, client_write_iv,
                                            client_seq_num, APPLICATION_DATA, REQUEST)
send_tls(s, APPLICATION_DATA, encrypted_msg)
client_seq_num += 1

print("Receiving an answer")
while True:
    try:
        rec_type, msg = recv_tls_and_decrypt(s, server_write_key, server_write_iv, server_seq_num)
        server_seq_num += 1
    except BrokenPipeError:
        print("Connection closed on TCP level")
        break

    if rec_type == APPLICATION_DATA:
        print(msg.decode(errors='ignore'))
    elif rec_type == HANDSHAKE:
        NEW_SESSION_TICKET = 4
        if msg[0] == NEW_SESSION_TICKET:
            print(f"New session ticket: {msg.hex()}")
    elif rec_type == ALERT:
        alert_level, alert_description = msg

        print(f"Got alert level: {alert_level}, description: {alert_description}")
        CLOSE_NOTIFY = 0
        if alert_description == CLOSE_NOTIFY:
            print("Server sent close_notify, no waiting for more data")
            break
    else:
        print("Got msg with unknown rec_type", rec_type)
