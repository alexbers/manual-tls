# manual-tls #

Makes HTTPS connection with TLS 1.3 in pure Python. The only used import is
socket! All required crypto algos are implemented manually.

Implemented algos: AES128 with GCM, SHA256, HMAC, Elliptic Curve Diffie-Helman

This is educational project. The goal is to make the code as simple and
readable as possible. Please, don't use it in your production projects, it
is not secure.

## Motivation ##

Have you ever wandered what happens when you type some HTTPS address in
your browser? Which packets are sent? What algorithms are involved?

Many programs use libraries for doing HTTPS connections, e.g. NSS or
OpenSSL. These libraries conceal protocol details behind their API and make
things not interesting and magic-like. Their code is very difficult to
read.

This project implements TLS manually. It doesn't try to implement all possible
key-exchange and encryption protocols. Instead it implements only one -
TLS 1.3 with Elliptic Curve Diffie-Hellman key exchange, AES-128
encryption in Galois/Counter mode and SHA256 hashing algo. Also it does not
support advanced features like client's authentication, session tickets, etc.
It even doesn't support server certificate chain validation.

This program will help you to find an answer on "What if ...?" questions about
the TLS protocol. Also this project can be used to test corner cases in your
favorite TLS server implementation.

## Similar projects ##

* Toytls: https://github.com/bjornedstrom/toytls
* Tlslite: http://trevp.net/tlslite/

## Links ##

* RFC about TLS 1.3: https://tools.ietf.org/html/rfc8446
* Russian description of TLS protocol: https://tls.dxdt.ru/tls.html

## Requirements ##

* >= Python 3.6

## Usage ##

    python tls_client.py

## Example of output ##

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
        Cipher suites len is 2: 0002
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
        Server random: 7d0867f7f9814befda07ccec518fa23a07eaa874bbc5cb36223b21dc85aba6a7
        Session id len is 0: 00
        Session id:
        Cipher suite is TLS_AES_128_GCM_SHA256: 1301
        Compression method is no compression: 00
        Extensions len is 79: 004f
        Extension parsing was skipped, but public_ec_key is 04cf840b4b61ae6c3cbbebf06e16cecf6d75f3473e8457c5d648bca7bd9ccb82848c77d441519b19a7c3ebe5d335a3c035e5fa66f0a90e6f5a6f986e994963a734
        Server ECDH public key: x=93862061420779749527918971620573008759231845401823265734290741304190978196100 y=63535518533582075225080723395323933324721906588633935768241485717907964143412
    Receiving a change cipher msg, all communication will be encrypted
        Our common ECDH secret is: 68fbe2618e3d9cc585733ffa5ed7cdbb793fbd81bbc940996723c8f473374bbb, deriving keys
        handshake_secret 6ddf921791f2bb0521af0617777c53a41486e5249b468963be41c471c6951d57
        server_write_key 58df059f0af13844427e3354adc3733d
        server_write_iv b545a99f9fa977ad255c4879
        server_finished_key c1277ff5e4eeb661a66add9249fe16440e05e58899a08a57d8a45ba54e2aadb7
        client_write_key 184d86dee2e140767902cdc22299f64f
        client_write_iv ffb9dfb1ff5c5b1abdb32320
        client_finished_key 88d4da04377fa2b02ec770cc08a0432a4fa51a4bfaca5b5f901361b18339c29a
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
        Client finish value 1f5db6b7d73d9265f8f767fa2af050e7ab2625677f2e85fdc0ebce8bb5ea95e2
    Handshake finished, regenerating secrets for application data
        premaster_secret d39fcfd67d25d056a0834783553dd18b1d70f0166b648db627d20447e61def4f
        master_secret 54a5528c5a766827043f14f46a284c3948f9d3c5ee978008b1fdc5040b39a513
        server_secret 1191f2e46968ab71c43b6dda9a1e4342fbbe77e7746f0aeed735e7216c000d4f
        server_write_key f2a2f5ab798d3b6bc7b8805d2f0e3416
        server_write_iv 823e5412dd934cfe73bca937
        client_secret 66f987b63ce607162d89d0df52e0cab995d8c3893f145b5c797eecd9b674358e
        client_write_key 5a3d05e240ba40042208a8b8bac2d89c
        client_write_iv c7ed9c63f5f397ffb2e3d1d2
    Sending b'HEAD /ru/company/habr/blog/522330/ HTTP/1.1\r\nHost: habr.com\r\nConnection: close\r\n\r\n'
    Receiving an answer
    HTTP/1.1 200 OK
    Server: QRATOR
    Date: Thu, 08 Oct 2020 00:36:08 GMT
    Content-Type: text/html; charset=UTF-8
    Connection: close
    Vary: Accept-Encoding
    Vary: Accept-Encoding
    X-Frame-Options: SAMEORIGIN
    P3P: CP="CAO DSP COR CURa ADMa DEVa PSAa PSDa IVAi IVDi CONi OUR OTRi IND PHY ONL UNI FIN COM NAV INT DEM STA"
    X-Content-Type-Options: nosniff
    Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
    Public-Key-Pins: pin-sha256="jWWta3ma1DSx8lFr6uv04x6sSRmK5X4Z0ivIL7+qKLM="; pin-sha256="Efde6ZPsmxzZkludmzwnp0QJhZ1mSwHrhDxczbpZcmM="; pin-sha256="klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY="; pin-sha256="kUh5F9diW5KlrhQ+nEKTIVFWVZuNbVqkKtm+KOGPXCE="; max-age=15552000
    X-Proxy-Cache-Status: EXPIRED
    X-Proxy-Upstream: habrcom-engine


    Got alert level: 1, description: 0
    Server sent close_notify, no waiting for more data
