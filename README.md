# manual-tls #

A simple example of manual tls 1.0 connection with Diffie–Hellman key exchange

## Motivation ##

This is educational project about cryptography. Please, don't use it in your 
production projects!

Have you ever wandered what happens when you type some https address in 
your browser? Which packets are sent? What algorithms are involved?

Many programs use libraries for doing https connections, e.g. nss or 
openssl. This libraries conceal protocol details behind their api and make
things not interesting and magic-like. And their code are very difficult to 
read.

This python project implements tls manually. It not tries to implement all 
variety of key-exchange and encryption protocols. Instead it implements only 
one - TLS 1.0 with Diffie-Hellman key exchange, AES-256 encryption with 
Cipher-block chaining and SHA1 hashing algo. Also it not supports advanced 
features like client's authentication, compression, session tickets, etc. It
even doesn't support server certificate chain validation. But without all this 
the code is sipmpler.

This program will help you to find an answer on "What if ...?" questions about 
the tls protocol.

## Similar projects ##

* Toytls: https://github.com/bjornedstrom/toytls
* Tlslite: http://trevp.net/tlslite/

## Requirements ##

* Python 2.7
* M2Crypto python module

## Usage ##

    python ./tls_client.py

## Example of output ##

    python ./tls_client.py
    Connecting to github.com:443
    Connected
    Handshake: sending a client hello
    Client random: abababababababababababababababababababababababababababababababab
    Handshake: receiving a server hello
    Server random: 52188c48a855635f30ecb7545e03dd404d10f7c17eeb56d1bef4ceef30399315
    Session id: bee37baa9bd27eebf840636ad15773bff73292cb51a647bc0db27884138ae048
    Handshake: receiving a server certs
    Got 2 certs
    Handshake: receiving a server key exchange
    DH prime: 131832052042219009527839525934268128127355300704472845128573174908898587826481581974548040446189688518070214483643209695723925616113897243950922364670371766056432630785982773485713108424273657672047098239473476944390258716112687012012440120129627988472009949456811428528912427249964927042573604085259319733147
    DH generator: 2
    DH pubkey: 92454083147536215278532856519066192368883844731139229080924501095541400998024915932816834054403258635798547123970390834144100608339586731968707079091174187308700521564317264518483416776451393921700354757826617289200106082987128020061066319858855429845879358845380850837217571925158021325608930706240613472192
    DH signature: 6047065701028992716818632060448382071202726765434984281455736411347647983346684188939877558465309708389514331827374353834669846707582970323054340679040435670337779266355181478983130056753441403766322678266421636215381672113444688830441474630894472917402912593022578898701740025439471756279004307525970634004776001361255794185901276883025807528504535703198510217407159042130643745545324657907827043674191923471321015512484383504946933609391405307191811453096605094547924929084293247209887778813405038989305696211134630206763480711539340445244650147914375844204743769214289016458116860795335881141523424365504407687683
    Server DH signature is VALID
    Handshake: receiving a server hello done
    My DH pubkey: 1024
    Our common DH secret is: 97267960869107953109881187378338303835639720570132520636754872918637513920764217017184117079182842467271878699538723464054889103652194214296449126769594839770867288711797154902753313727207217908908556250514754168221740791468015216636023936076306151890272003777557987603605621144159039749484253789102348835416
    Handshake: sending a client key exchange
    Our master secret: 33a942ae74558b202eb1ade5d290fd828d8709fa61fd316673130df244cb8896f7ac88b5a584477ada0cbe54120bff47
    Our keyblock: 6218bc708b115be353c7c40da8ee1d31c5fb387de896abf78229b3e63460beff98d0c95a3acb98ff099fab8b5ccd5c17408863cf8c9bc7b3129715e47ee8932e10310513992e9f9102bcd3deb06203540d6f15e5b8d6888063c9b77d159d331607594e3bb22e682a550a9f478e17d964a9f1370a28108977c3273216650c566336712b74f0c6c12b
    Mac key: 6218bc708b115be353c7c40da8ee1d31c5fb387d, key: 099fab8b5ccd5c17408863cf8c9bc7b3129715e47ee8932e10310513992e9f91, iv: 550a9f478e17d964a9f1370a28108977
    Client finish val: 80c734e77a6815316893b03b
    Handshake: sending a change cipher msg
    Handshake: sending an encrypted handshake msg
    Server finish val: 170437ba32d6a763521b3dbd
    Handshake: receiving a change cipher msg
    Handshake: receiving an encrypted handshake msg
    Msg mac is valid: True, server finish val is valid: True
    Handshake finished
    Sending GET /
    Receiving an answer
    Got: <html><body>You are being <a href="https://github.com/dashboard">redirected</a>.</body></html>
    Got alert level: 1, description: 0
    Server sent close_notify, no waiting for more data



