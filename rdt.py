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
        # extract the fields
        seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        return self(seq_num, msg_S)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    def get_sequence_number(self):
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        return seq_num_S

    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length: Packet.seq_num_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[
                     Packet.seq_num_S_length + Packet.seq_num_S_length: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length:]

        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''
    last_successful_bit = 0

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
        # keep extracting packets - if reordered, could get more than one
        while True:
            # check if we have received enough bytes
            if (len(self.byte_buffer) < Packet.length_S_length):
                return ret_S  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            # remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last packet, will return on the next iteration

    def rdt_2_1_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        # print(p.get_byte_S())
        self.seq_num = (self.seq_num + 1) % 2
        # print(self.seq_num)
        #Sending the message
        self.network.udt_send(p.get_byte_S())

        # After we send the message, we wait for ACK
        waiting_for_ACK = True
        while (waiting_for_ACK):
            #received_bit = self.network.udt_receive()
            byte_seq = self.network.udt_receive()

            #Get the sequence number, and check if it matches our packet sequence number
            #If it does, good, do nothing. Otherwise, resend the previous packet
            if (int(byte_seq) == self.seq_num):
                waiting_for_ACK = False

            # If we get the wrong bit, we resend our old packet, and continue waiting
            else:
                print("Received NACK")
                self.network.udt_send(p.get_byte_S())

        # Wait for response (ACK or NACK)
        #   if ACK, continue
        #
        #   if NACK, repeat

    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        #self.byte_buffer += byte_S     moved down like 15 lines
        packet = Packet(None, None)


        #if (len(byte_S) > 0):
            #print(byte_S)
            #packet = Packet.from_byte_S(byte_S)
            #print(packet.get_byte_S())
            #print(packet.get_sequence_number())


        #If the packet is not corrupt, send ACK as 0 or 1, and deliver packet
        packet_is_valid = not Packet.corrupt(byte_S)
        if (packet_is_valid):
            sequence_number = packet.get_sequence_number()
            self.network.udt_send(sequence_number)

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

        #If the packet wasn't valid, send a NAK, and wait for the response
        #This will send the other sequence number, indicating the packet was not received correctly
        else:
            sequence_number = packet.get_sequence_number()
            self.network.udt_send((sequence_number+1) % 2)
            #print("Packet was invalid (corrupt or checksums don't match.")


    def rdt_3_0_send(self, msg_S):
        pass

    def rdt_3_0_receive(self):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(1)
        #sleep(50000)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()


    else:
        sleep(2)
        #sleep(30000)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()




