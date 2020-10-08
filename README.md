# Manual TLS #

Makes HTTPS connection with TLS 1.3 in 100% Python. The only used import is
**socket**! All required crypto algorithms are implemented manually in a
single file.

Implemented algos: AES128 with GCM, SHA256, HMAC and Diffie-Hellman on
Elliptic Curves

This program will help you to find answers on "What if ...?" questions about
the TLS protocol. Also this project can be used to test corner cases in your
favorite TLS server implementation.

This is educational project. The goal is to make the code as simple and
as readable as possible. The security and performance are not priorities of
this project. Please, don't use it in your production projects, **it
is not secure**.

## Motivation ##

Have you ever wandered what happens when you type an HTTPS address in
the browser? What data is sent? What algorithms are involved to make the
connection secure?

Many programs use libraries for making HTTPS connections like *NSS* or
*OpenSSL*. These libraries conceal protocol details behind their API and make
things magic-like. Their code is very difficult to read. The aim of this
project is to **reveal this magic**, showing how the things look like in
the **low level**.

We don't try to implement all possible key-exchange and encryption protocols,
we implement only the most standard ones: TLS 1.3 with Elliptic Curve
Diffie-Hellman for key exchange, AES-128 in Galois/Counter mode for encryption
and SHA256 for hashing. Also we don't support advanced features like client's
authentication, session tickets, etc. We even do not support server's
certificate chain validation.

## Links ##

* RFC about TLS 1.3: https://tools.ietf.org/html/rfc8446
* Russian description of TLS protocol: https://tls.dxdt.ru/tls.html

## Requirements ##

* at least Python 3.6

## Usage ##

    python tls_client.py

## Example of Output ##

    Connecting to habr.com:443
    Generating params for a client hello, the first message of TLS handshake
        Client random: abababababababababababababababababababababababababababababababab
        Our ECDH (Elliptic-curve Diffie-Hellman) private key: 42
        Our ECDH public key: x=46815746278116120727102909818790311888606566061375401374185894328395891209484 y=27468372135271391475594175804425777961752385311825500239867916238362509316710
    Generating the client hello
        Type is the client hello: 01
        Length is 141: 00008d
        Legacy client version is TLS 1.2: 0303
        Client random: abababababababababababababababababababababababababababababababab
        Session id len is 0: 00
        Session id:
        Cipher suites len is 2: b'\x00\x02'
        Cipher suite is TLS_AES_128_GCM_SHA256: 1301
        Compression method len is 1: 01
        Compression method is no compression: 00
        Extensions len is 98: 0062
        Extension type is supported_versions: 002b
            Extension len is 3: 0003
            Extension field len is 2: 02
            Version is TLS 1.3: 0304
        Extension type is signature_algos: 000d
            Extension len is 4: 0004
            Extension field len is 2: 0002
            Algo is rsa_pss_rsae_sha256_algo: 0804
        Extension type is supported_groups: 000a
            Extension len is 4: 0004
            Extension field len is 2: 0002
            Group is secp256r1_group: 0017
        Extension type is key_share: 0033
            Extension len is 71: 0047
            Extension field len is 69: 0045
            Key length 65: 0041
            Key is: 046780c5fc70275e2c7061a0e7877bb174deadeb9887027f3fa83654158ba7f50c3cba8c34bc35d20e81f730ac1c7bd6d661a942f90c6a9ca55c512f9e4a001266
    Sending the client hello
    Receiving a server hello
        Type is the server hello: 02
        Length is 119: 000077
        Legacy server version is TLS 1.2: 000077
        Server random: c11a1177c4813353751cfaf27133905ad67f77ed88fc21670c62a199aa313fa1
        Session id len is 0: 00
        Session id:
        Cipher suite is TLS_AES_128_GCM_SHA256: 1301
        Compression method is no compression: 00
        Extensions len is 79: 004f
        Extension parsing was skipped, but public_ec_key is 0478003800c23a787ea83d793f7b74cb59862c0b24053d7d97614f3694301e88b26b53b5a0f99438551dad252dd63c50bac255eac741269f91b1596b77a577d57b
        Server ECDH public key: x=54277928348242024903757613031064122054132624276698172392055208349862522161330 y=48545376660750080108352403742441326749980023007443021874724088967974482335099
    Receiving a change cipher msg, all communication will be encrypted
        Our common ECDH secret is: 9205da5653751539e6f0e7f24be9015a5ffe223f6692abfc55f5eb7802f9cf39, deriving keys
        handshake_secret 3c6bd5481af6f8e435e9c4fbcf1214b435376e7160c2fb4e6fda15f70142a6fb
        server_write_key 22a3f0f8e9645cecb76328b0f6e5bc38
        server_write_iv 42f7ad832c77842ebef068be
        server_finished_key 2abf4b824eb2d5e4fc6fb0627cb9c9afae72772ae9a5e5ba5dd4492d1a901e4d
        client_write_key e1ec0567486a4980026beab638eb4d9d
        client_write_iv b25c0a3b9f1b0e3c1967f803
        client_finished_key 93f080ab75f57aa4d8e3c55e384ba0ad8efc5c7944c19de96414634053886a4f
    Receiving encrypted extensions
        Encrypted_extensions: 0800000c000a000a00060004001d0017, parsing skipped
    Receiving server certificates
        Got 1 certs
    Receiving server verify certificate
        Certificate verifying skipped
    Receiving server finished
        Warning: Server sent wrong handshake finished msg
    Handshake: sending a change cipher msg
    Handshake: sending an encrypted finished msg
        Client finish value 19cf601a487f1eb125c111673db463af060a7adf22afe906b8de9222f8e017bd
    Handshake finished, regenerating secrets for application data
        premaster_secret bde7d6a47d199f4f9467580f7ed30981ff41a94731afb4f6c06b8b11358563bc
        master_secret 18824f3bb44d2f4557fe047ab86efb806cb2fe1cd135f428af23468da2f157dc
        server_secret 23f1122780875c189cf6e504a7561193eb10f4863a05f56de25a2ae72cbf81c4
        server_write_key 8d8d331677efc6f52d03bcdf84c149bb
        server_write_iv 7350df09bdc275fa2f800d2b
        client_secret 68d0d96196cc1ab96d363630538460aad322c4418c91f700a1611b6a55cfdc1d
        client_write_key 8b9efd6dfcb0727f84d758aa8fedc854
        client_write_iv cf7d945f75b6de412af2a89c
    Sending b'HEAD /ru/company/habr/blog/522330/ HTTP/1.1\r\nHost: habr.com\r\nConnection: close\r\n\r\n'
    Receiving an answer
    New session ticket: 040000d5000002584a2fe8a608000000000000000000c0c0d25bee58afd3061043b8a5e218aec437a09d4b4dd387774bb7fe80f9ceeb97d1bc15a91ee8c63d3ce54e4028e19d35a51f304e0b924eebe17f402dea96d25f0f66124e7a6f9db7f688050b235d849f7e001ceb0d9efe6c6df0a64481c3f02a10e92408fd7d6322ed4a149562c1afbee454546f8220e0fd8a6783ad1e7e7328fbd450eb626ff725de8cbad4aed2c5d88ddf6209303cf85381e5a29760d561b01e5f71e81ed84d717db0e90d069e4769064c932f8c033c89947bcba3e7f9db930000
    New session ticket: 040000d50000025835af2a4508000000000000000100c0c0d25bee58afd3061043b8a5e218aec4789eb477a8cf2aa26e0519d869b2b5610958bef21421d71705f01a81aac0f3fe2a2fbe93b2c36520db5924ddd13cc4a609ccbece097e297894dd2b1b4ac0bf677bdda9a7c65eb3f5426118670092fd6d206b128302f370766d77a470971c188ba2c867b5f9519a57eed056d11f79b27f2b74d614f0db6b379b7956396daeab1038da321b7b351ef840eb5c032704e708aee0cbcadd73fc9f01ce7e40d4bf69a283c8f58114efce467de7377835d320fb0000
    HTTP/1.1 200 OK
    Server: QRATOR
    Date: Thu, 08 Oct 2020 19:38:18 GMT
    Content-Type: text/html; charset=UTF-8
    Connection: close
    Vary: Accept-Encoding
    Vary: Accept-Encoding
    X-Powered-By: PHP/7.2.32-1+ubuntu16.04.1+deb.sury.org+1
    X-Frame-Options: SAMEORIGIN
    P3P: CP="CAO DSP COR CURa ADMa DEVa PSAa PSDa IVAi IVDi CONi OUR OTRi IND PHY ONL UNI FIN COM NAV INT DEM STA"
    X-Content-Type-Options: nosniff
    Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
    Public-Key-Pins: pin-sha256="jWWta3ma1DSx8lFr6uv04x6sSRmK5X4Z0ivIL7+qKLM="; pin-sha256="Efde6ZPsmxzZkludmzwnp0QJhZ1mSwHrhDxczbpZcmM="; pin-sha256="klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY="; pin-sha256="kUh5F9diW5KlrhQ+nEKTIVFWVZuNbVqkKtm+KOGPXCE="; max-age=15552000
    X-Proxy-Cache-Status: EXPIRED
    X-Proxy-Upstream: habrcom-engine


    Got alert level: 1, description: 0
    Server sent close_notify, no waiting for more data
