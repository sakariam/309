import socket
import struct
import time
import argparse

# Constants
HEADER_LEN = 6
MAX_PAYLOAD_LEN = 994
MAX_PACKET_LEN = HEADER_LEN + MAX_PAYLOAD_LEN
PACKET_FORMAT = "!H H H"

# Flag bit masks
SYN_FLAG = 0b1000  # Connection initiation
ACK_FLAG = 0b0100  # Acknowledgment
FIN_FLAG = 0b0010  # Connection termination
DATA_FLAG = 0b0001  # Data packet

# Packet structure definition
class Packet:
    def __init__(self, seq, ack, flags, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload

    def pack(self):
        # Convert packet to bytes for transmission
        header = struct.pack(PACKET_FORMAT, self.seq, self.ack, self.flags)
        return header + self.payload

    @staticmethod
    def unpack(packet_bytes):
        # Convert bytes back to a packet object
        header = packet_bytes[:HEADER_LEN]
        seq, ack, flags = struct.unpack(PACKET_FORMAT, header)
        payload = packet_bytes[HEADER_LEN:]
        return Packet(seq, ack, flags, payload)

# Helper to calculate throughput in Mbps
def calculate_throughput(bytes_sent, start_time, end_time):
    time_elapsed = end_time - start_time
    throughput = (bytes_sent * 8) / (time_elapsed * 1_000_000)
    return throughput

# Server class for receiving and acknowledging packets
class Server:
    def __init__(self, ip, port, filename, window_size):
        self.ip = ip
        self.port = port
        self.filename = filename
        self.window_size = window_size
        self.expected_seq = 1  # Next expected in-order packet
        self.received_data = {}  # Buffer for storing all received data
        self.out_of_order = {}  # Buffer for storing out-of-order packets
        self.start_time = None
        self.end_time = None

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.ip, self.port))
        print("Server is listening...")

        while True:
            data, client_address = server_socket.recvfrom(MAX_PACKET_LEN)
            packet = Packet.unpack(data)

            # Handle SYN (connection initiation)
            if packet.flags & SYN_FLAG:
                print("SYN packet received")
                syn_ack_packet = Packet(0, packet.seq + 1, SYN_FLAG | ACK_FLAG)
                server_socket.sendto(syn_ack_packet.pack(), client_address)
                print("SYN-ACK packet sent")

            # Handle ACK (connection establishment confirmation)
            elif packet.flags & ACK_FLAG and not (packet.flags & DATA_FLAG):
                print("ACK packet received, connection established")
                self.start_time = time.time()

            # Handle FIN (connection termination)
            elif packet.flags & FIN_FLAG:
                print("FIN packet received")
                fin_ack_packet = Packet(packet.seq, packet.seq + 1, ACK_FLAG)
                server_socket.sendto(fin_ack_packet.pack(), client_address)
                print("FIN ACK packet sent")
                self.end_time = time.time()
                break

            # Handle data packets
            elif packet.flags & DATA_FLAG:
                if packet.seq == self.expected_seq:
                    # In-order packet received
                    print(f"Packet {packet.seq} received in order")
                    self.received_data[packet.seq] = packet.payload
                    self.expected_seq += 1

                    # Process buffered out-of-order packets
                    while self.expected_seq in self.out_of_order:
                        self.received_data[self.expected_seq] = self.out_of_order.pop(self.expected_seq)
                        self.expected_seq += 1

                    # Send cumulative ACK
                    ack_packet = Packet(0, self.expected_seq, ACK_FLAG)
                    server_socket.sendto(ack_packet.pack(), client_address)

                elif packet.seq > self.expected_seq:
                    # Out-of-order packet, buffer it
                    print(f"Packet {packet.seq} received out of order")
                    if packet.seq not in self.out_of_order:
                        self.out_of_order[packet.seq] = packet.payload

                    # Send ACK for current expected sequence (cumulative ACK)
                    ack_packet = Packet(0, self.expected_seq, ACK_FLAG)
                    server_socket.sendto(ack_packet.pack(), client_address)

                else:
                    # Duplicate packet, ACK again
                    print(f"Duplicate packet {packet.seq} received")
                    ack_packet = Packet(0, self.expected_seq, ACK_FLAG)
                    server_socket.sendto(ack_packet.pack(), client_address)

        # Save all received data to a file
        with open(self.filename, "wb") as f:
            for seq in sorted(self.received_data):
                f.write(self.received_data[seq])

        # Print performance
        throughput = calculate_throughput(sum(len(data) for data in self.received_data.values()), self.start_time, self.end_time)
        print(f"Throughput: {throughput:.2f} Mbps")
        print("Connection closed")

# Client class for sending file packets using a sliding window
class Client:
    def __init__(self, ip, port, filename, window_size):
        self.ip = ip
        self.port = port
        self.filename = filename
        self.window_size = window_size
        self.base = 1  # First unacknowledged packet
        self.next_seq = 1  # Next sequence number to use
        self.packets = {}  # Sequence number to data mapping
        self.start_time = None
        self.end_time = None

    def start(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(0.5)

        # Initiate connection with SYN
        syn_packet = Packet(0, 0, SYN_FLAG)
        client_socket.sendto(syn_packet.pack(), (self.ip, self.port))
        print("SYN packet sent")

        # Wait for SYN-ACK and send final ACK
        while True:
            try:
                data, _ = client_socket.recvfrom(MAX_PACKET_LEN)
                packet = Packet.unpack(data)
                if packet.flags & (SYN_FLAG | ACK_FLAG):
                    print("SYN-ACK received")
                    ack_packet = Packet(packet.ack, packet.seq + 1, ACK_FLAG)
                    client_socket.sendto(ack_packet.pack(), (self.ip, self.port))
                    print("ACK sent, connection established")
                    break
            except socket.timeout:
                client_socket.sendto(syn_packet.pack(), (self.ip, self.port))
                print("SYN retransmitted")

        # Prepare packets to send
        with open(self.filename, "rb") as f:
            seq = 1
            while True:
                data = f.read(MAX_PAYLOAD_LEN)
                if not data:
                    break
                self.packets[seq] = data
                seq += 1

        total_packets = len(self.packets)
        self.start_time = time.time()

        # Main sending loop with sliding window
        while self.base <= total_packets:
            # Send all packets in window
            while self.next_seq < self.base + self.window_size and self.next_seq <= total_packets:
                packet = Packet(self.next_seq, 0, DATA_FLAG, self.packets[self.next_seq])
                client_socket.sendto(packet.pack(), (self.ip, self.port))
                print(f"Packet {self.next_seq} sent")
                self.next_seq += 1

            try:
                # Listen for ACK
                data, _ = client_socket.recvfrom(MAX_PACKET_LEN)
                packet = Packet.unpack(data)
                if packet.flags & ACK_FLAG:
                    ack_num = packet.ack
                    print(f"ACK {ack_num - 1} received")
                    if ack_num - 1 >= self.base:
                        self.base = ack_num  # Slide window forward
            except socket.timeout:
                # Timeout occurred; retransmit window
                for seq in range(self.base, self.next_seq):
                    packet = Packet(seq, 0, DATA_FLAG, self.packets[seq])
                    client_socket.sendto(packet.pack(), (self.ip, self.port))
                    print(f"Packet {seq} retransmitted")

        # Send FIN to close connection
        fin_packet = Packet(self.next_seq, 0, FIN_FLAG)
        client_socket.sendto(fin_packet.pack(), (self.ip, self.port))
        print("FIN packet sent")

        # Wait for ACK of FIN
        while True:
            try:
                data, _ = client_socket.recvfrom(MAX_PACKET_LEN)
                packet = Packet.unpack(data)
                if packet.flags & ACK_FLAG:
                    print("FIN ACK received")
                    self.end_time = time.time()
                    break
            except socket.timeout:
                client_socket.sendto(fin_packet.pack(), (self.ip, self.port))
                print("FIN retransmitted")

        # Print performance
        throughput = calculate_throughput(sum(len(data) for data in self.packets.values()), self.start_time, self.end_time)
        print(f"Throughput: {throughput:.2f} Mbps")
        print("Connection closed")
        client_socket.close()

# Command-line argument parsing
def parse_args():
    parser = argparse.ArgumentParser(description='Reliable UDP File Transfer')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--server', action='store_true', help='Run as server')
    group.add_argument('-c', '--client', action='store_true', help='Run as client')
    parser.add_argument('-i', '--ip', type=str, required=True, help='IP address')
    parser.add_argument('-p', '--port', type=int, required=True, help='Port number')
    parser.add_argument('-f', '--file', type=str, required=True, help='File name')
    parser.add_argument('-w', '--window_size', type=int, default=4, help='Window size')
    return parser.parse_args()

# Entry point
def main():
    args = parse_args()
    if args.server:
        server = Server(args.ip, args.port, args.file, args.window_size)
        server.start()
    elif args.client:
        client = Client(args.ip, args.port, args.file, args.window_size)
        client.start()

if __name__ == "__main__":
    main()