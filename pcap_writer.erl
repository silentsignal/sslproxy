-module(pcap_writer).
-record(pcap_fd, {io_dev}).
-export([open/3, write_packet/2, write_packet/3, write_packet/4, close/1]).

-define(MAGIC_NUMBER, 16#a1b2c3d4).
-define(VERSION_MAJOR, 2).
-define(VERSION_MINOR, 4).


open(Filename, SnapLength, DataLinkType)
  when is_integer(SnapLength), is_integer(DataLinkType) ->
    case file:open(Filename, [write]) of
        {ok, IoDevice} ->
            write_header(IoDevice, SnapLength, DataLinkType),
            {ok, #pcap_fd{io_dev=IoDevice}};
        {error, _} = Error -> Error
    end.


write_header(IoDevice, SnapLength, DataLinkType) ->
    file:write(IoDevice,
               <<?MAGIC_NUMBER:32, ?VERSION_MAJOR:16, ?VERSION_MINOR:16,
                 0:64, % GMT to local correction (32), accuracy (32), both zero
                 SnapLength:32, DataLinkType:32>>).


write_packet(PcapFd, Packet) ->
    write_packet(PcapFd, os:timestamp(), Packet).

write_packet(PcapFd, TimeStamp, Packet) when is_binary(Packet) ->
    write_packet(PcapFd, TimeStamp, byte_size(Packet), Packet).

write_packet(#pcap_fd{io_dev=IoDevice}, {MegaSec, Sec, MicroSec}, ActualLength,
             Packet) when is_integer(ActualLength), is_binary(Packet) ->
    Seconds = MegaSec * 1000000 + Sec,
    InclLen = byte_size(Packet),
    file:write(IoDevice,
               [<<Seconds:32, MicroSec:32, InclLen:32, ActualLength:32>>,
                Packet]).


close(#pcap_fd{io_dev=IoDevice}) ->
    file:close(IoDevice).
