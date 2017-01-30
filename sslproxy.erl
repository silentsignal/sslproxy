-module(sslproxy).
-export([start/0, acceptor/2]).

-define(LISTEN_PORT, 8083).
-define(CA_KEY_FILE, "burpkey.pem").
-define(CA_CERT_FILE, "burpcert-fixed.pem").

-define(DLT_RAW, 101).

-include_lib("public_key/include/public_key.hrl").

-record(cert, {cn, der}).
-record(rt_cfg, {ca_key_der, ca_key_decoded, ca_cert, passthrough}).

start() ->
	case file:consult("config.txt") of
		{ok, Config} ->
			application:start(crypto),
			application:start(asn1),
			application:start(public_key),
			application:start(ssl),
			ListenPort = proplists:get_value(listen_port, Config),
			{ok, ProxyListenSock} = gen_tcp:listen(ListenPort, [binary,
				{active, false}, {packet, http}, {reuseaddr, true}]),
			{ok, PemBin} = file:read_file(proplists:get_value(ca_cert_file, Config)),
			[{'Certificate', DER, not_encrypted} | _] = public_key:pem_decode(PemBin),
			{ok, KPemBin} = file:read_file(proplists:get_value(ca_key_file, Config)),
			[{'RSAPrivateKey' = T, RSA, not_encrypted} | _] = public_key:pem_decode(KPemBin),
			Key = public_key:der_decode(T, RSA),
			CACert = public_key:pkix_decode_cert(DER, otp),
			PT = lists:map(fun compile_pt_re/1, proplists:get_value(passthrough, Config, [])),
			RuntimeConfig = #rt_cfg{ca_key_der={T, RSA}, ca_key_decoded=Key,
				ca_cert=CACert, passthrough=PT},
			acceptor(ProxyListenSock, RuntimeConfig);
		{error, Reason} ->
			io:format("Couldn't load config.txt: ~s~n", [file:format_error(Reason)])
	end.

compile_pt_re(Value) ->
    {ok, RE} = re:compile(Value, [caseless]),
    RE.

acceptor(ProxyListenSock, Config) ->
    {PcapFd, Certs} = receive
        {'ETS-TRANSFER', C, Parent, P} when is_pid(Parent) -> {P, C}
    after 0 ->
        {open_pcap_file(), ets:new(certs, [{keypos, #cert.cn}, public])}
    end,
    {ok, Sock} = gen_tcp:accept(ProxyListenSock),
    Heir = spawn(?MODULE, acceptor, [ProxyListenSock, Config]),
    ets:give_away(Certs, Heir, PcapFd),
    gen_tcp:controlling_process(ProxyListenSock, Heir),
    {Host, Port} = get_target(Sock),
    inet:setopts(Sock, [{packet, raw}]),
    gen_tcp:send(Sock, <<"HTTP/1.1 200 Connection established\r\n"
                         "Proxy-agent: sslproxy\r\n\r\n">>),
    io:format("Sent response headers, accepting SSL for ~s...~n", [Host]),
    put(pcap_fd, PcapFd),
    case should_mitm(Host, Port, Config#rt_cfg.passthrough) of
        true -> mitm_ssl(Sock, Host, Port, Certs, Config);
        false -> passthrough(Sock, Host, Port)
    end.

should_mitm(Host, Port, PTL) ->
    Subject = [Host, $:, integer_to_list(Port)],
    lists:all(fun (RE) -> re:run(Subject, RE) =:= nomatch end, PTL).

passthrough(Sock, Host, Port) ->
    inet:setopts(Sock, [{active, true}]),
    io:format("Lettings SSL pass through, connecting to ~s:~p~n", [Host, Port]),
    case gen_tcp:connect(Host, Port, [{packet, raw}, {active, true}, {mode, binary}]) of
        {ok, TargetSock} ->
            calc_ip_headers(Sock, TargetSock, inet),
            forwarder(Sock, TargetSock);
        {error, Reason} ->
            io:format("Couldn't connect to target: ~p~n", [Reason]),
            gen_tcp:close(Sock)
    end.

mitm_ssl(Sock, Host, Port, Certs, Config) ->
    {ok, SslSocket} = ssl:ssl_accept(Sock, [{cert, get_cert_for_host(Host, Certs, Config)},
                                            {key, Config#rt_cfg.ca_key_der},
                                            {active, true}, {packet, raw}]),
    io:format("Accepted SSL, connecting to ~s:~p~n", [Host, Port]),
    case ssl_connect_with_fallback(Host, Port) of
        {ok, TargetSock} ->
            case ssl:recv(SslSocket, 0) of
                {ok, Data} ->
                    calc_ip_headers(SslSocket, TargetSock, ssl),
                    self() ! {ssl, SslSocket, Data},
                    forwarder(SslSocket, TargetSock);
                {error, Reason} ->
                    io:format("Couldn't receive from client: ~p~n", [Reason]),
                    ssl:close(SslSocket),
                    ssl:close(TargetSock)
            end;
        {error, Reason} ->
            io:format("Couldn't connect to target: ~p~n", [Reason]),
            ssl:close(SslSocket)
    end.

ssl_connect_with_fallback(Host, Port) ->
    Versions = proplists:get_value(available, ssl:versions()),
    ssl_connect_with_fallback(Host, Port, Versions, false, unknown).
ssl_connect_with_fallback(_, _, [], _, Error) -> Error;
ssl_connect_with_fallback(Host, Port, Versions, Fallback, _) ->
    Options = [{verify, verify_none}, {packet, raw}, {active, true},
               {mode, binary}, {versions, Versions}, {fallback, Fallback}],
    case ssl:connect(Host, Port, Options) of
        {ok, _} = R -> R;
        {error, _} = R -> ssl_connect_with_fallback(Host, Port, tl(Versions), true, R)
    end.

open_pcap_file() ->
    PcapFile = lists:append(["/tmp/sslproxy-", os:getpid(), "-",
            base64:encode_to_string(term_to_binary(erlang:timestamp())), ".pcap"]),
    {ok, P} = pcap_writer:open(PcapFile, 65535, ?DLT_RAW),
    io:format("Opened PCAP output file ~s~n", [PcapFile]),
    P.

calc_ip_headers(Client, Server, Module) ->
    {CA, CP} = peername_bin(Client, Module),
    {SA, SP} = peername_bin(Server, Module),
    put({Client, Server}, {<<16#40, 0, 64, 6, 0, 0, CA/binary, SA/binary,
                             CP/binary, SP/binary>>, 0, 0}),
    put({Server, Client}, {<<16#40, 0, 64, 6, 0, 0, SA/binary, CA/binary,
                             SP/binary, CP/binary>>, 0, 0}).

peername_bin(Socket, Module) ->
    {ok, {{A, B, C, D}, Port}} = Module:peername(Socket),
    {<<A, B, C, D>>, <<Port:16>>}.

forwarder(Socket1, Socket2) ->
    Continue = receive
        {ssl, Socket1, Data} ->
            relay_data(Socket1, Socket2, Data, ssl),
            true;
        {ssl, Socket2, Data} ->
            relay_data(Socket2, Socket1, Data, ssl),
            true;
        {tcp, Socket1, Data} ->
            relay_data(Socket1, Socket2, Data, gen_tcp),
            true;
        {tcp, Socket2, Data} ->
            relay_data(Socket2, Socket1, Data, gen_tcp),
            true;
        {ssl_closed, Socket1} -> ssl:close(Socket2), false;
        {ssl_closed, Socket2} -> ssl:close(Socket1), false;
        {tcp_closed, Socket1} -> gen_tcp:close(Socket2), false;
        {tcp_closed, Socket2} -> gen_tcp:close(Socket1), false;
        {ssl_error, S, _} when S =:= Socket1; S =:= Socket2 -> false;
        {tcp_error, S, _} when S =:= Socket1; S =:= Socket2 -> false;
        Other -> io:format("Unexpected message: ~p\n", [Other]), true
    end,
    case Continue of
        true -> forwarder(Socket1, Socket2);
        false -> ok
    end.

relay_data(From, To, Data, Module) ->
    Module:send(To, Data),
    {IpAddrsTcpPorts, Ident, Seq} = get({From, To}),
    {_, _, Ack} = get({To, From}),
    put({From, To}, {IpAddrsTcpPorts, Ident + 1, Seq + byte_size(Data)}),
    Packet = <<16#45, 0, (byte_size(Data) + 40):16, Ident:16, IpAddrsTcpPorts/binary,
               Seq:32, Ack:32, 16#50, 8, 16#FFFF:16, 0:32, Data/binary>>,
    pcap_writer:write_packet(get(pcap_fd), Packet).

get_cert_for_host(Host, Certs, Config) ->
    case ets:lookup(Certs, Host) of
        [C] -> C#cert.der;
        [] ->
            DER = gen_cert_for_host(Host, Config),
            ets:insert(Certs, #cert{cn=Host, der=DER}),
            DER
    end.

gen_cert_for_host(Host, Config) ->
    {Y, M, D} = date(),
    NotBefore = lists:flatten(io_lib:format("~w~2..0w~2..0w000000Z", [Y, M, D])),
    NotAfter  = lists:flatten(io_lib:format("~w~2..0w~2..0w000000Z", [Y + 10, M, D])),
    Subject = [[#'AttributeTypeAndValue'{type=?'id-at-commonName',
                                         value={utf8String, list_to_binary(Host)}}]],
    LeafCert = Config#rt_cfg.ca_cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'{
                  serialNumber=erlang:unique_integer([positive]),
                  signature=#'SignatureAlgorithm'{algorithm=?'sha256WithRSAEncryption',
                                                  parameters='NULL'},
                  validity=#'Validity'{notBefore={generalTime, NotBefore},
                                       notAfter ={generalTime, NotAfter}},
                  subject={rdnSequence, Subject}
                 },
    public_key:pkix_sign(LeafCert, Config#rt_cfg.ca_key_decoded).

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
