-module(sslproxy).
-export([start/0, acceptor/1]).

-define(LISTEN_PORT, 8083).
-define(CA_KEY_FILE, "burpkey.pem").
-define(CA_CERT_FILE, "burpcert-fixed.pem").
-define(PRIV_KEY_FILE, "mitmkey.pem").

-define(DLT_RAW, 101).

-record(cert, {cn, der}).

start() ->
    application:start(crypto),
    application:start(asn1),
    application:start(public_key),
    application:start(ssl),
    {ok, ProxyListenSock} = gen_tcp:listen(?LISTEN_PORT, [binary,
        {active, false}, {packet, http}, {reuseaddr, true}]),
    acceptor(ProxyListenSock).

acceptor(ProxyListenSock) ->
    {PcapFd, Certs} = receive
        {'ETS-TRANSFER', C, Parent, P} when is_pid(Parent) -> {P, C}
    after 0 ->
        {open_pcap_file(), ets:new(certs, [{keypos, #cert.cn}, public])}
    end,
    {ok, Sock} = gen_tcp:accept(ProxyListenSock),
    Heir = spawn(?MODULE, acceptor, [ProxyListenSock]),
    ets:give_away(Certs, Heir, PcapFd),
    gen_tcp:controlling_process(ProxyListenSock, Heir),
    {Host, Port} = get_target(Sock),
    inet:setopts(Sock, [{packet, raw}]),
    gen_tcp:send(Sock, <<"HTTP/1.1 200 Connection established\r\n"
                         "Proxy-agent: sslproxy\r\n\r\n">>),
    {ok, SslSocket} = ssl:ssl_accept(Sock, [{cert, get_cert_for_host(Host, Certs)},
                                            {keyfile, ?PRIV_KEY_FILE},
                                            {active, true}, {packet, raw}]),
    case ssl:connect(Host, Port, [{verify, verify_none}, {packet, raw},
                                  {active, true}, {mode, binary}]) of
        {ok, TargetSock} ->
            case ssl:recv(SslSocket, 0) of
                {ok, Data} ->
                    put(pcap_fd, PcapFd),
                    calc_ip_headers(SslSocket, TargetSock),
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

open_pcap_file() ->
    PcapFile = lists:append(["/tmp/sslproxy-", os:getpid(), "-",
            base64:encode_to_string(term_to_binary(erlang:timestamp())), ".pcap"]),
    {ok, P} = pcap_writer:open(PcapFile, 65535, ?DLT_RAW),
    io:format("Opened PCAP output file ~s~n", [PcapFile]),
    P.

calc_ip_headers(Client, Server) ->
    {CA, CP} = peername_bin(Client),
    {SA, SP} = peername_bin(Server),
    put({Client, Server}, {<<16#40, 0, 64, 6, 0, 0, CA/binary, SA/binary,
                             CP/binary, SP/binary>>, 0, 0}),
    put({Server, Client}, {<<16#40, 0, 64, 6, 0, 0, SA/binary, CA/binary,
                             SP/binary, CP/binary>>, 0, 0}).

peername_bin(Socket) ->
    {ok, {{A, B, C, D}, Port}} = ssl:peername(Socket),
    {<<A, B, C, D>>, <<Port:16>>}.

forwarder(Socket1, Socket2) ->
    Continue = receive
        {ssl, Socket1, Data} ->
            relay_data(Socket1, Socket2, Data),
            true;
        {ssl, Socket2, Data} ->
            relay_data(Socket2, Socket1, Data),
            true;
        {ssl_closed, Socket1} -> ssl:close(Socket2), false;
        {ssl_closed, Socket2} -> ssl:close(Socket1), false;
        {ssl_error, S, _} when S =:= Socket1; S =:= Socket2 -> false;
        Other -> io:format("Unexpected message: ~p\n", [Other]), true
    end,
    case Continue of
        true -> forwarder(Socket1, Socket2);
        false -> ok
    end.

relay_data(From, To, Data) ->
    ssl:send(To, Data),
    {IpAddrsTcpPorts, Ident, Seq} = get({From, To}),
    {_, _, Ack} = get({To, From}),
    put({From, To}, {IpAddrsTcpPorts, Ident + 1, Seq + byte_size(Data)}),
    Packet = <<16#45, 0, (byte_size(Data) + 40):16, Ident:16, IpAddrsTcpPorts/binary,
               Seq:32, Ack:32, 16#50, 8, 16#FFFF:16, 0:32, Data/binary>>,
    pcap_writer:write_packet(get(pcap_fd), Packet).

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
