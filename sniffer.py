import argparse
import json
import os
from datetime import datetime
from google.protobuf.json_format import MessageToDict
from scapy.all import *
from scapy.layers.inet import TCP
from colorama import Fore, Style

from proto.cmdid import cmd_ids


parsed_packets = []


payload = None
def parse_honkai_packet(packet):
    # Large packets are fragmented. Stitch them together before parsing them ...
    # This is probably buggy af :skull:
    global payload
    current_payload = bytes(packet[TCP].payload)
    if int.from_bytes(current_payload[0:4], byteorder="big") == 0x1234567:
        payload = bytearray(current_payload)
    else:
        if payload:
            payload.extend(current_payload)
        else:
            return None

    if len(payload) < 38:
        return None

    if int.from_bytes(payload[-4:], byteorder="big") != 0x89abcdef:
        return None

    # Parse the packet.
    head_magic = int.from_bytes(payload[0:4], byteorder="big")
    packet_version = int.from_bytes(payload[4:6], byteorder="big")
    client_version = int.from_bytes(payload[6:8], byteorder="big")
    time = int.from_bytes(payload[8:12], byteorder="big")
    user_id = int.from_bytes(payload[12:16], byteorder="big")
    user_ip = int.from_bytes(payload[16:20], byteorder="big")
    user_session_id = int.from_bytes(payload[20:24], byteorder="big")
    cmd_id = int.from_bytes(payload[24:28], byteorder="big")
    server_header_len = int.from_bytes(payload[28:30], byteorder="big")
    body_len = int.from_bytes(payload[30:34], byteorder="big")

    server_header = payload[34:34+server_header_len]

    body_start = 34 + server_header_len
    body = payload[body_start:body_start+body_len]
    tail_magic = int.from_bytes(payload[body_start+body_len:body_start+body_len+4], byteorder="big")

    if head_magic != 0x1234567 or tail_magic != 0x89abcdef:
        return None

    # Try to parse the packet body as a protobuf message.
    packet_name = ""
    body_parsed = None
    if cmd_id in cmd_ids:
        packet_name = cmd_ids[cmd_id].__name__

        try:
            body_parsed = cmd_ids[cmd_id]()
            body_parsed.ParseFromString(body)
            body_parsed = MessageToDict(body_parsed)
        except:
            body_parsed = None

    # Add to the result.
    res = {
        "source": "CLIENT" if packet[TCP].dport == args.port else "SERVER",
        "payload": payload.hex(),
        "parsed": {
            "head_magic": head_magic,
            "packet_version": packet_version,
            "client_version": client_version,
            "time": time,
            "user_id": user_id,
            "user_ip": user_ip,
            "user_session_id": user_session_id,
            "cmd_id": cmd_id,
            "server_header_len": server_header_len,
            "body_len": body_len,
            "server_header": server_header.hex(),
            "body": body.hex(),
            "tail_magic": tail_magic,
            "packet_name": packet_name,
            "body_parsed": body_parsed,
        }
    }

    if tail_magic == 0x89abcdef:
        payload = None

    return res
    

def print_packet(parsed_packet, args):
    # Time
    print(f"{datetime.now().strftime('%H:%M:%S')} | ", end="")

    # Direction
    print(f"{Fore.GREEN if parsed_packet['source'] == 'CLIENT' else Fore.BLUE}{parsed_packet['source']}{Style.RESET_ALL} | ", end="")
    # Command
    command = parsed_packet["parsed"]["packet_name"]

    if command != "":
        print(f"{Fore.YELLOW}{command}{Style.RESET_ALL}{' ' * (30 - len(command)) if len(command) <= 30 else ''} | ", end="")
    else:
        print(f"{Fore.RED}UNKNOWN{Style.RESET_ALL}{' ' * 23} | ", end="")

    #Content
    if (args.short and parsed_packet["parsed"]["body_len"]>int(args.short)):
        print(f"{Fore.MAGENTA}HIDDEN{Style.RESET_ALL}")
    else: 
        print(f'{parsed_packet["parsed"]["body_parsed"]}')

    # Separator
    print("-" * (os.get_terminal_size().columns - 1))

#Seems to be broken
def read_from_pcap(args):
    # Construct PCAP reader.
    pcap_reader = PcapReader(args.pcap)

    # Iterate packets in the PCAP and extract Honkai packets.
    for packet in pcap_reader:
        # Make sure this is a Honkai packet.
        if packet[TCP].dstport == args.port or packet[TCP].srcport == args.port:
            parsed = parse_honkai_packet(packet)

            if parsed is not None:
                print_packet(parsed, args)
                parsed_packets.append(parsed)


def sniff_packets(args):
    def handle_sniffed(packet):
        parsed = parse_honkai_packet(packet)

        if parsed is not None:
            if args.included:
                if not(parsed["parsed"]["packet_name"] in args.included):return
            if args.excluded:
                if (parsed["parsed"]["packet_name"] in args.excluded):return
            print_packet(parsed, args)
            if not args.slim:
                parsed_packets.append(parsed)
            else:
                if args.included:
                    if (len(args.included) == 1):
                        parsed_packets.append(parsed["parsed"]["body_parsed"])
                else:
                    #can be modified if needed for more or less information
                    parsed_packets.append({
                        "message":parsed["parsed"]["packet_name"],
                        "content":parsed["parsed"]["body_parsed"]
                    })

    sniff(session=IPSession, filter="tcp port "+str(args.port), prn=handle_sniffed)
    

def main(args):
    if args.included and args.excluded:
        print("--include and --exclude are mutually exclusive.")
        return
    if args.pcap:
        # Read packets from the specified PCAP.
        read_from_pcap(args)
    else:
        sniff_packets(args)
    try:
        if args.short:int(args.short)
    except:
        print("input err")
    # Save packets to JSON.
    if args.output:
        with open(args.output, "w") as f:
            json.dump(parsed_packets, f, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", dest="pcap", required=False, help="The input PCAP file to read packets from. If none is specified, sniff from the network interface instead.")
    parser.add_argument("--output", dest="output", required=False, help="The output JSON file to which the packets should be written.")
    parser.add_argument("--short", dest="short", required=False, help="Maximum body size console output.")
    parser.add_argument("--port", dest="port", required=False, default=16100)
    parser.add_argument("--slim", dest="slim", required=False, default=True, help="Bool, enables slim data output, Default=True") # Setting Value to false will force include all packet meta data, default is to only include body_parsed
    parser.add_argument("--exclude", dest="excluded", nargs="+", required=False, help="A list of packets that should be excluded from terminal output. They will still be written to the outputted JSON file.")
    parser.add_argument("--included", dest="included", nargs="+", required=False, help="A list of packets that should be included from terminal output. They will still be written to the outputted JSON file.")
    args = parser.parse_args()

    main(args)
