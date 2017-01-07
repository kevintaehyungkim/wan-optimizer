import utils
import tcp_packet
import collections
import wan_optimizer

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        self.stored_payloads = {}
        self.stored_blocks = collections.defaultdict(str)


    def send_message(self, packet, payload, dest, key = None):

        if key and key in self.stored_payloads.keys():
                self.send(tcp_packet.Packet(packet.src, packet.dest, False, packet.is_fin, key), dest)
                return

        elif key and key not in self.stored_payloads.keys():
                self.stored_payloads[key] = payload

        while (len(payload) > utils.MAX_PACKET_SIZE):
            new_packet = tcp_packet.Packet(packet.src, packet.dest, True, False, payload[:utils.MAX_PACKET_SIZE])
            payload = payload[utils.MAX_PACKET_SIZE:]

            self.send(new_packet, dest)

        self.send(tcp_packet.Packet(packet.src, packet.dest, True, packet.is_fin, payload), dest)


    def receive(self, packet):
        #Handles receiving a packet.
       
        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            if packet.is_raw_data:
                path = packet.src + " " + packet.dest 
                self.stored_blocks[path] += packet.payload

                if len(self.stored_blocks[path]) >= 48:
                    BITSTRING = utils.get_last_n_bits(utils.get_hash(self.stored_blocks[path][len(self.stored_blocks[path])-48:]), 13)
                    if BITSTRING == self.GLOBAL_MATCH_BITSTRING or packet.is_fin:
                        key = utils.get_hash(self.stored_blocks[path])
                        self.stored_payloads[key] = self.stored_blocks[path]
                        self.send_message(packet, self.stored_blocks[path], self.address_to_port[packet.dest])
                        self.stored_blocks[path] = ""
                elif packet.is_fin:
                    key = utils.get_hash(self.stored_blocks[path])
                    self.stored_payloads[key] = self.stored_blocks[path]
                    self.send_message(packet, self.stored_blocks[path], self.address_to_port[packet.dest])
                    self.stored_blocks[path] = ""
            else:
                path = packet.src + " " + packet.dest 
                self.stored_blocks[path] = ""
                self.send_message(packet, self.stored_payloads[packet.payload], self.address_to_port[packet.dest])
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            if packet.is_raw_data:
                path = packet.src + " " + packet.dest 
                self.stored_blocks[path] += packet.payload 

                if len(self.stored_blocks[path]) > 48:
                    start = 0
                    end = max(48, len(self.stored_blocks[path]) - packet.size())
                    while end <= len(self.stored_blocks[path]):
                        BITSTRING = utils.get_last_n_bits(utils.get_hash(self.stored_blocks[path][end-48:end]), 13)
                        if BITSTRING == self.GLOBAL_MATCH_BITSTRING:
                            key = utils.get_hash(self.stored_blocks[path][start:end])
                            self.send_message(packet, self.stored_blocks[path][start:end], self.wan_port, key=key)

                            self.stored_blocks[path] = self.stored_blocks[path][end:]
                            start = end
                            end += 48
                        else:
                            end += 1
                if packet.is_fin:
                    if len(self.stored_blocks[path])>0:
                        key = utils.get_hash(self.stored_blocks[path])
                        self.send_message(packet, self.stored_blocks[path], self.wan_port, key=key)
                    else:
                        self.send_message(packet, self.stored_blocks[path], self.wan_port)
                    self.stored_blocks[path] = ""
            else:
                path = packet.src + " " + packet.dest
                self.send(packet, self.wan_port)