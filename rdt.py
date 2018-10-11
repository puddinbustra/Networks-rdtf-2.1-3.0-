#Hugh's starting code stuff

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
     #   print(seq_num," is seq num")
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
        #convert length to a byte field of length_S_length byte
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
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
            
    
                
#All below must deal with packet corruption


#rdt 2.1  does:  237 of pdf has pic
#Error detection(corruption)
#Receiver feedback (NAK OR ACK)
#Retransmission - aka NAK
             #- not entirely sure what that means, so I won't add that yet
#Also deals with garbled NAKs and ACKs
    def rdt_2_1_send(self, msg_S):
        #Make checksum - not clear if this is already taken care of or needs to be here. Corrupt() might have it down

        #Wait for call from above, make packet, then send packet
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())


        #seq = 0

        # Wait for ACK 0
        #     Receive packet and check for corruption
        #         Ask to resend if necessary and stay in this state
        #         otherwise move on

        #Wait for call 1
            #Same as call 0

        #Wait for ACK 1
            #Same as ACK 0
        
    def rdt_2_1_receive(self):
        #The sequence number that's currently saved
        #This is important because if the seq nums themselves aren't 0 or 1, we can use this to dictate if the state
        #should change as a result
        seq_saved = 0

        #If state == 0, it is waiting for ack or nak 0
        #If state == 1, it is waiting for ack or nak 1
        #starting in 0, just because that seems right
        state = 0
        #extract packet, then deliver data
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

            #Hugh adding this
            seq_num_S = byte_S[Packet.length_S_length: Packet.seq_num_S_length + Packet.seq_num_S_length]

            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            # remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last packet, will return on the next iteration
            if state == 0:
                #If it's corrupt or a duplicate
                if Packet.corrupt(byte_S) or seq_num_S == seq_saved:
                    #Then resend last packet

                #If packet is not corrupt, then unpack and deliver it, so don't do much
                else:
                    state = 1
                    #If it's odd, then it's a 1, if it's even it's a 0
                    seq_saved = seq_num_S % 2

            # If state == 1, do the same thingish
            else:
                if Packet.corrupt(byte_S) or seq_num_S == seq_saved:
                    #Then resend last packet
                    
                # If packet is not corrupt, then unpack and deliver it, so don't do much
                else:
                    seq_saved = seq_num_S % 2
                    state = 0

        #2 states - wait for 0 or wait for 1:

        #Waiting for seq 0
        #Send packet parts and receive packet part(checks for corruption)

        #Waiting for seq 1
        #Send packet parts and receive packet part(checks for corruption)

        pass


    #RDT 3.0 adds timeouts, and adds an extra index bit to check order
    def rdt_3_0_send(self, msg_S):
        #Wait for call 0
            #After first time:
                #Also continuously receive packets (it looks like anyway)

            #Send packet
            #Start timer

        #Wait for ACK 0
            #Receive packet and check for corruption continuously
                #Ask to resend if necessary and stay in this state
                #otherwise move on
                #restart timer
            #Timeout
                #Resend packet, restart timer

        #Wait for call 1
            #May need extra rcv packet call

            #Same as call 0 down here

        #Wait for ACK 1
            #Same as ACK 0
        pass


    def rdt_3_0_receive(self):
        #Wait for 0 seq
            #Receive forever, and check if corrupt or has seq1
                #Then resend
        #Then receive packet forever, checking for corruption and having seq 0
            #Extract, deliver data and then make packet with ACK0,checksum and send it

        #Wait for 1 seq
            #Same as 0 seq

        #Then same as 0 seq
        pass

        
#Don't need below, just look above :)
if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        
