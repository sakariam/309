import socket
import argparse
import struct
import threading
import time
import os
from datetime import datetime

# Constants for packet structure and behavior
HEADER_FORMAT = '!HHHH'        # Network byte order: seq_num (16 bits), ack_num (16), flags (16), recv_window (16)
HEADER_SIZE = 8                # 4 fields * 2 bytes = 8 bytes
DATA_SIZE = 992                # Max application data size
PACKET_SIZE = HEADER_SIZE + DATA_SIZE
TIMEOUT = 0.4                  # 400 ms retransmission timeout

# Flag definitions (bit-masks)
FLAG_FIN = 1                   # End of file/data
FLAG_ACK = 2                   # Acknowledgment
FLAG_SYN = 4                   # Connection initiation (SYN)

# ================================
# Description:
#     Constructs a UDP packet with DRTP header and payload
# Arguments:
#     seq     : Sequence number of the packet
#     ack     : Acknowledgment number
#     flags   : DRTP control flags (SYN, ACK, FIN)
#     recv_win: Receiver window size
#     data    : Application layer payload (<=992 bytes)
# Returns:
#     A bytes object of full packet (header + data)
# ================================
def build_packet(seq=0, ack=0, flags=0, recv_win=0, data=b''):
    header = struct.pack(HEADER_FORMAT, seq, ack, flags, recv_win)
    return header + data

# ================================
# Description:
#     Parses a received packet into header fields and data
# Arguments:
#     packet: Full packet received (bytes)
# Returns:
#     Tuple of (seq_num, ack_num, flags, recv_window, data)
# ================================
def parse_packet(packet):
    header = packet[:HEADER_SIZE]
    data = packet[HEADER_SIZE:]
    seq, ack, flags, recv_win = struct.unpack(HEADER_FORMAT, header)
    return seq, ack, flags, recv_win, data

# ================================
# Description:
#     Server function to receive and write a file using DRTP
# Arguments:
#     ip         : IP address to bind to
#     port       : Port number to listen on
#     discard_seq: Optional packet number to discard once (for testing retransmissions)
# Behavior:
#     Establishes connection via 3-way handshake, receives data, acknowledges in-order packets,
#     and tears down the connection on FIN.
# Returns:
#     None
# ================================
def run_server(ip, port, discard_seq):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"Server listening on {ip}:{port}")

    expected_seq = 1
    received_data = {}         # Stores received data chunks by sequence number
    discard_once = True if discard_seq != float('inf') else False

    start_time = time.time()
    total_bytes = 0
    connection_established = False

    while True:
        try:
            packet, client_addr = sock.recvfrom(PACKET_SIZE)
            seq, ack, flags, recv_win, data = parse_packet(packet)
            timestamp = datetime.now().time()

            if flags & FLAG_SYN:
                print("SYN packet is received")
                syn_ack = build_packet(0, 0, FLAG_SYN | FLAG_ACK, 15)
                sock.sendto(syn_ack, client_addr)
                print("SYN-ACK packet is sent")

            elif flags & FLAG_ACK and not connection_established:
                print("ACK packet is received")
                print("Connection established")
                connection_established = True

            elif flags & FLAG_FIN:
                print("FIN packet is received")
                fin_ack = build_packet(0, 0, FLAG_FIN | FLAG_ACK, 0)
                sock.sendto(fin_ack, client_addr)
                print("FIN ACK packet is sent")
                break

            elif connection_established and data:
                if seq == discard_seq and discard_once:
                    print(f"{timestamp} -- packet {seq} is received and DISCARDED")
                    discard_once = False
                    continue

                if seq == expected_seq:
                    print(f"{timestamp} -- packet {seq} is received")
                    received_data[seq] = data
                    ack_pkt = build_packet(0, seq, FLAG_ACK, 0)
                    sock.sendto(ack_pkt, client_addr)
                    print(f"{timestamp} -- sending ack for the received {seq}")
                    expected_seq += 1
                    total_bytes += len(data)
                else:
                    print(f"{timestamp} -- unexpected packet {seq}, expected {expected_seq}")
        except Exception as e:
            print("Error receiving packet:", e)
            continue

    end_time = time.time()
    throughput = (total_bytes * 8) / (end_time - start_time) / 1_000_000  # Mbps
    print(f"\nThe throughput is {throughput:.2f} Mbps")
    print("Connection Closes")

    try:
        with open("received_file", "wb") as f:
            for i in sorted(received_data):
                f.write(received_data[i])
    except IOError as e:
        print("Error writing file:", e)

# ================================
# Description:
#     Client function to send a file using DRTP with Go-Back-N
# Arguments:
#     file_path  : Path to the source file to send
#     ip         : Receiver's IP address
#     port       : Receiver's port
#     window_size: Sender's sliding window size
# Behavior:
#     Establishes connection, sends file using Go-Back-N,
#     waits for ACKs, handles timeouts, and gracefully tears down
# Returns:
#     None
# ================================
def run_client(file_path, ip, port, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    addr = (ip, port)

    # ---- Connection Setup ----
    try:
        syn = build_packet(flags=FLAG_SYN)
        sock.sendto(syn, addr)
        print("SYN packet is sent")

        synack = sock.recv(PACKET_SIZE)
        _, _, flags, recv_win, _ = parse_packet(synack)
        if flags & FLAG_SYN and flags & FLAG_ACK:
            print("SYN-ACK packet is received")
            send_window = min(window_size, recv_win)
            ack = build_packet(flags=FLAG_ACK)
            sock.sendto(ack, addr)
            print("ACK packet is sent")
            print("Connection established")
        else:
            print("Handshake failed")
            return
    except socket.timeout:
        print("Connection timeout.")
        return

    # ---- File Preparation ----
    try:
        with open(file_path, "rb") as f:
            chunks = [chunk for chunk in iter(lambda: f.read(DATA_SIZE), b'')]
    except IOError as e:
        print("File read error:", e)
        return

    base = 1
    next_seq = 1
    total_packets = len(chunks)
    acked = set()
    lock = threading.Lock()

    # ---- Timeout and Retransmission Thread ----
    def timeout_handler():
        nonlocal base, next_seq
        while base <= total_packets:
            time.sleep(TIMEOUT)
            with lock:
                if base not in acked:
                    print(f"Timeout: Resending from packet {base}")
                    for i in range(base, min(base + send_window, total_packets + 1)):
                        send_packet(i)

    # ================================
    # Description:
    #     Sends one packet with given sequence number
    # Arguments:
    #     seq: sequence number to send
    # Behavior:
    #     Constructs packet and sends it via UDP
    # ================================
    def send_packet(seq):
        data = chunks[seq - 1]
        pkt = build_packet(seq=seq, data=data)
        sock.sendto(pkt, addr)
        print(f"{datetime.now().time()} -- packet with seq = {seq} is sent, sliding window = {list(range(base, min(base + send_window, total_packets + 1)))}")

    threading.Thread(target=timeout_handler, daemon=True).start()

    # ---- Sliding Window and ACK Loop ----
    while base <= total_packets:
        with lock:
            while next_seq < base + send_window and next_seq <= total_packets:
                send_packet(next_seq)
                next_seq += 1

        try:
            ack_pkt, _ = sock.recvfrom(PACKET_SIZE)
            _, ack_num, flags, _, _ = parse_packet(ack_pkt)
            if flags & FLAG_ACK:
                print(f"{datetime.now().time()} -- ACK for packet = {ack_num} is received")
                with lock:
                    acked.add(ack_num)
                    if ack_num == base:
                        while base in acked:
                            base += 1
        except socket.timeout:
            continue

    print("DATA Finished")

    # ---- Connection Teardown ----
    try:
        fin = build_packet(flags=FLAG_FIN)
        sock.sendto(fin, addr)
        print("FIN packet is sent")

        finack, _ = sock.recvfrom(PACKET_SIZE)
        _, _, flags, _, _ = parse_packet(finack)
        if flags & FLAG_FIN and flags & FLAG_ACK:
            print("FIN ACK packet is received")
            print("Connection Closes")
    except socket.timeout:
        print("Timeout waiting for FIN ACK")

# ================================
# Main Entry Point
# Parses arguments and runs server/client accordingly
# ================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DRTP File Transfer Application")
    parser.add_argument("-s", "--server", action="store_true", help="Enable server mode")
    parser.add_argument("-c", "--client", action="store_true", help="Enable client mode")
    parser.add_argument("-i", "--ip", type=str, default="127.0.0.1", help="IP address")
    parser.add_argument("-p", "--port", type=int, default=8088, help="Port number [1024–65535]")
    parser.add_argument("-f", "--file", type=str, help="File to send")
    parser.add_argument("-w", "--window", type=int, default=3, help="Sliding window size")
    parser.add_argument("-d", "--discard", type=int, default=float('inf'), help="Seq # to discard (server-side test)")

    args = parser.parse_args()

    if args.server:
        run_server(args.ip, args.port, args.discard)
    elif args.client:
        if not args.file:
            print("Please specify a file with -f")
        else:
            run_client(args.file, args.ip, args.port, args.window)
    else:
        print("Please specify --client or --server mode")
