import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    def derive_checksum(self, byte_string):
        print("_________")
        print(type(byte_string))
        print(byte_string)
        print("___________")
        sequence_number_start_index = self.length_S_length
        print(sequence_number_start_index)
        checksum_start_index = sequence_number_start_index + self.seq_num_S_length
        print(checksum_start_index)
        message_start_index = checksum_start_index + self.checksum_length
        print(message_start_index)

        length = byte_string[0 : sequence_number_start_index]
        print(length)
        sequence_num = byte_string[sequence_number_start_index : checksum_start_index]
        print(sequence_num)
        checksum = byte_string[checksum_start_index : message_start_index]
        print(checksum)
        message = byte_string[message_start_index :]
        print(message)

        byte_string_without_checksum = length + sequence_num + message
        checksum = hashlib.md5((byte_string_without_checksum).encode('utf-8'))
        hexdecimal_checksum = checksum.hexdigest()
        return hexdecimal_checksum

    def get_received_checksum(self, byte_string):
        ##print(byte_string)
        sequence_number_start_index = self.length_S_length
        checksum_start_index = sequence_number_start_index + self.seq_num_S_length
        message_start_index = checksum_start_index + self.checksum_length

        received_checksum = byte_string[checksum_start_index : message_start_index]
        return received_checksum
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    last_successful_bit = 1

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    
    def rdt_2_1_send(self, msg_S):
        self.seq_num = (self.seq_num + 1) % 2
        packet = Packet(self.seq_num, msg_S)
        bytes_of_sent_message = packet.get_byte_S()
        self.network.udt_send(bytes_of_sent_message)
        
    def rdt_2_1_receive(self):
        received_message = None
        received_bytes = self.network.udt_receive()
        self.byte_buffer += received_bytes

        checksum_packet = Packet(None, None)
        locally_calculated_checksum = checksum_packet.derive_checksum(received_bytes)
        print("hereherehere is recieved byte")
        print(received_bytes)
        print(type(received_bytes))
        received_checksum = checksum_packet.get_received_checksum(received_bytes)

        print("ok")
        print(locally_calculated_checksum)
        print(received_checksum)

        bytes_are_corrupted = locally_calculated_checksum != received_checksum
        print(bytes_are_corrupted)

        '''while (bytes_are_corrupted):
            self.network.udt_send(str(self.last_successful_bit))
            received_bytes = self.network.udt_receive()
            locally_calculated_checksum = checksum_packet.derive_checksum(received_bytes)
            received_checksum = checksum_packet.get_received_checksum(received_bytes)
            bytes_are_corrupted = locally_calculated_checksum != received_checksum'''



        number_of_bits_to_describe_message_length = Packet.length_S_length
        while True:
            if(len(self.byte_buffer) < number_of_bits_to_describe_message_length):
                return received_message
            length =\
                int(self.byte_buffer[:number_of_bits_to_describe_message_length])
            if len(self.byte_buffer) < length:
                return received_message
            packet = Packet.from_byte_S(self.byte_buffer[0:length])
            received_message += packet.msg_S
            self.byte_buffer = self.byte_buffer[length:]
    
    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(5000)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()

    else:
        sleep(3000)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        