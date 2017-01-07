import tcp_packet
import utils
import wan_optimizer

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).

        # Map hashes to blocks of data
        self.block_dict = {}

        # Current buffer fullness for each destination
        self.packet_bits = {}
        self.stored_block = {}
        self.stored_packets = {}

    def send_block(self, rtpack, packet_array):
        # Send the packets in the block
        for packet in packet_array:
            new_packet = tcp_packet.Packet(rtpack.src, rtpack.dest, packet.is_raw_data, packet.is_fin, packet.payload)
            if rtpack.dest in self.address_to_port:
                # The packet is destined to one of the clients connected to this middlebox;
                # send the packet there.
                self.send(new_packet, self.address_to_port[new_packet.dest])
            else:
                # The packet must be destined to a host connected to the other middlebox
                # so send it across the WAN.
                self.send(new_packet, self.wan_port)

    def receive(self, packet):
        # Handles receiving a packet.

        if packet.dest not in self.packet_bits:
            # If we havent sent anything to this destination yet make the buffer
            self.packet_bits[packet.dest] = 0
        if packet.dest not in self.stored_block:
            # If we havent sent anything to this destination yet make the buffer
            self.stored_block[packet.dest] = ""    
        if packet.dest not in self.stored_packets:
            # If we havent sent anything to this destination yet make the buffer
            self.stored_packets[packet.dest] = []

        if packet.is_raw_data:
            # If we're receiving raw data then hash the data if block is full
            if self.packet_bits[packet.dest] + packet.size() >= self.BLOCK_SIZE:
                # If block is full reset send it
                # How much overflow and offset
                overflow = self.packet_bits[packet.dest] + packet.size() - self.BLOCK_SIZE
                offset = packet.size() - overflow
                # Add the last packet or part of a packet
                if overflow == 0:
                    # Only set fin if no overflow
                    self.stored_packets[packet.dest].append(tcp_packet.Packet(packet.src, packet.dest, True, packet.is_fin, packet.payload[:offset]))
                else:
                    self.stored_packets[packet.dest].append(tcp_packet.Packet(packet.src, packet.dest, True, False, packet.payload[:offset]))
                self.stored_block[packet.dest] += packet.payload[:offset]
                # Check if we've seen this block before by hashing
                key = utils.get_hash(self.stored_block[packet.dest])
                # Check if the hash is in the dictionary
                if key in self.block_dict:
                    # If the hash is in the dictionary send the key it corresponds to
                    new_packet = tcp_packet.Packet(packet.src, packet.dest, False, packet.is_fin, key)
                    self.send(new_packet, self.wan_port)
                else:
                    # If the hash isn't in the dictionary add it and send the raw data
                    self.block_dict[key] = self.stored_packets[packet.dest]
                    self.send_block(packet, self.stored_packets[packet.dest])
                # Reset the variables
                self.packet_bits[packet.dest] = overflow
                self.stored_block[packet.dest] = ""
                self.stored_packets[packet.dest] = []
                # Store the rest of the overflow bits if there are any
                if overflow != 0:
                    self.stored_block[packet.dest] = packet.payload[offset:]
                    self.stored_packets[packet.dest].append(tcp_packet.Packet(packet.src, packet.dest, True, packet.is_fin, packet.payload[offset:]))
            else:
                self.packet_bits[packet.dest] += packet.size()
                self.stored_block[packet.dest] += packet.payload
                self.stored_packets[packet.dest].append(packet)
                if packet.is_fin:
                    # If the packet's done but we haven't hit the block size hash/send it anyway
                    key = utils.get_hash(self.stored_block[packet.dest])
                    # Check if the hash is in the dictionary
                    if key in self.block_dict:
                        # If the hash is in the dictionary send the key it corresponds to
                        new_packet = tcp_packet.Packet(packet.src, packet.dest, False, False, key)
                        self.send(new_packet, self.wan_port)
                    else:
                        # If the hash isn't in the dictionary add it and send the raw data
                        self.block_dict[key] = self.stored_packets[packet.dest]
                        self.send_block(packet, self.stored_packets[packet.dest])
                    # Reset the variables
                    self.packet_bits[packet.dest] = 0
                    self.stored_block[packet.dest] = ""
                    self.stored_packets[packet.dest] = []
        else:
            # If the packet is a hash, which should only happen between wan optimizers, send the data
            self.send_block(packet, self.block_dict[packet.payload])
            self.packet_bits[packet.dest] = 0
            self.stored_block[packet.dest] = ""
            self.stored_packets[packet.dest] = []