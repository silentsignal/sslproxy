SSL proxy
=========

License
-------

This software is available under MIT license, see `LICENSE.txt`.

Dependencies
------------

 - recent Erlang distribution (tested on `Erlang/OTP 17 [erts-6.2]`)

Configuration
-------------

The four `-define` clauses at the top of `sslproxy.erl` should be edited.

 - `LISTEN_PORT` is the TCP port to listen on
 - `CA_KEY_FILE` and `CA_CERT_FILE` are the private key and certificate of a CA that is accepted by the clients to be attacked with MITM, both in PEM format

Building
--------

	erlc *.erl

Running
-------

	$ erl -s sslproxy
	Erlang/OTP 17 [erts-6.2] [source] [64-bit] [smp:4:4] [async-threads:10] [kernel-poll:false]

	Eshell V6.2  (abort with ^G)
	1> Opened PCAP output file /tmp/sslproxy-11107-g2gDYgAABYdiAA7Ga2IADDWM.pcap

The PCAP file name contains the PID or the erlang process and a timestamp
for uniqueness, and the file will contain the plaintext of everything
that went through the proxy.

Known bugs and limitations
--------------------------

 - Encrypted private keys are _NOT_ supported, PEM files should contain `-----BEGIN PRIVATE KEY-----`.
 - Erlang SSL/TLS implementations cannot handle X.509 certificates with a country field of more than two characters, both as a client and as a server. This unfortunately also means that Burp certificates with `PortSwigger` as their "country" cannot be used by this tool.
 - Only version 4 IP addresses are supported.
