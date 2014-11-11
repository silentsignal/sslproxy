-module(sslproxy).
-export([start/0, acceptor/2]).

-define(LISTEN_PORT, 8083).
-define(CA_KEY_FILE, "burpkey.pem").
-define(CA_CERT_FILE, "burpcert-fixed.pem").
-define(PRIV_KEY_FILE, "mitmkey.pem").

-record(cert, {cn, der}).

start() ->
	application:start(crypto),
	application:start(asn1),
	application:start(public_key),
	application:start(ssl),
	{ok, ProxyListenSock} = gen_tcp:listen(?LISTEN_PORT, [binary,
		{active, false}, {packet, http}, {reuseaddr, true}]),
	Certs = ets:new(certs, [{keypos, #cert.cn}, public]),
	acceptor(ProxyListenSock, [{certs, Certs}]).

acceptor(ProxyListenSock, Config) ->
	{ok, Sock} = gen_tcp:accept(ProxyListenSock),
	Certs = proplists:get_value(certs, Config),
	Heir = spawn(?MODULE, acceptor, [ProxyListenSock, Config]),
	ets:setopts(Certs, {heir, Heir, undefined}),
	gen_tcp:controlling_process(ProxyListenSock, Heir),
	{Host, Port} = get_target(Sock),
	io:format("HOST: ~p PORT: ~p\n", [Host, Port]),
	inet:setopts(Sock, [{packet, raw}]),
	gen_tcp:send(Sock, <<"HTTP/1.1 200 Connection established\r\n"
						 "Proxy-agent: sslproxy\r\n\r\n">>),
	{ok, SslSocket} = ssl:ssl_accept(Sock, [{cert, get_cert_for_host(Host, Certs)},
											{keyfile, ?PRIV_KEY_FILE}]),
	io:format("~p", [ssl:recv(SslSocket, 0)]), % XXX
	ssl:send(SslSocket, <<"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
		"Content-Length: 3\r\n\r\nfoo">>). % TODO connect to remote and bridge

get_cert_for_host(Host, Certs) ->
	case ets:lookup(Certs, Host) of
		[C] -> C#cert.der;
		[] ->
			DER = gen_cert_for_host(Host),
			ets:insert(Certs, #cert{cn=Host, der=DER}),
			DER
	end.

gen_cert_for_host(Host) ->
	validate_hostname(Host),
	CertCommand = "openssl req -new -key " ?PRIV_KEY_FILE " -batch "
			"-subj \"/CN=" ++ Host ++ "/OU=SSL Proxy/O=SSL Proxy/C=HU/\" "
			"| openssl x509 -req -days 3650 -CA " ?CA_CERT_FILE
			" -CAkey " ?CA_KEY_FILE " -CAcreateserial -outform DER 2>/dev/null",
	Port = erlang:open_port({spawn, CertCommand}, [exit_status, binary]),
	Cert = collect_cert(Port),
	receive {'EXIT', Port, normal} -> Cert end.

validate_hostname([]) -> ok;
validate_hostname([Char | Rest]) when (Char >= $0 andalso Char =< $9);
	  (Char >= $A andalso Char =< $Z); (Char >= $a andalso Char =< $z);
	  Char =:= $.; Char =:= $- -> validate_hostname(Rest).

collect_cert(Port) -> collect_cert(Port, <<>>).
collect_cert(Port, Acc) ->
	receive
		{Port, {data, D}} -> collect_cert(Port, <<Acc/binary, D/binary>>);
		{Port, {exit_status, 0}} -> Acc;
		{Port, {exit_status, _}} -> throw({openssl_cert_gen_failed, Acc})
	end.

get_target(Sock) ->
	{ok, Request} = gen_tcp:recv(Sock, 0),
	{http_request, "CONNECT", {scheme, Hostname, PortString}, _} = Request,
	recv_till_http_eoh(Sock),
	{Hostname, list_to_integer(PortString)}.

recv_till_http_eoh(Sock) ->
	{ok, Result} = gen_tcp:recv(Sock, 0),
	case Result of
		http_eoh -> ok;
		_ -> recv_till_http_eoh(Sock)
	end.
