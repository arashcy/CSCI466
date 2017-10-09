import Network
import argparse
from time import sleep
import hashlib

# transport layer

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
            
    
    # called from above, is passed the data to be delivered to receiver upper layer
    def rdt_2_1_send(self, msg_S):
        p = Packet(self.seq_num, msg_S) # creates new packet with the current sequence number and the message
        self.seq_num += 1 # increments sequence number
        
        while True:
            self.network.udt_send(p.get_byte_S()) # sends packet
            self.byte_buffer = '' # empties buffer?
            rcvpkt = '' # sets received packet to empty for now

            while rcvpkt == '': # while received packet is still empty, keep trying to get a response
                rcvpkt = self.network.udt_receive() # tries to receive a response and sets any response received to the received packet variable

            length = int(rcvpkt[:Packet.length_S_length]) # length of the packet that was received
            self.byte_buffer = rcvpkt[length:] # sets the length of the buffer to the length of the received packet

            if Packet.corrupt(rcvpkt[:length]): # checks if the received packet is corrupted or not
                print("\nACK/NAK packet corrupted\n") # if it is corrupted, print out corrupted
            else: # if the packet is not corrupt
                response = Packet.from_byte_S(rcvpkt[:length]) # not sure what this does
                if(response.seq_num < self.seq_num): # checks that the response was supposed to come before the current
                    ack = Packet(response.seq_num, '1') # create an ACK, set to 1
                    self.network.udt_send(ack.get_byte_S()) # sending something else?
                elif (response.msg_S == '1'): # if the response is an ACK
                    print("\nACK received\n") # then a packet was successfully sent
                    self.seq_num += 1 # the sequence number is incremented
                    break
                elif (response.msg_S == '0'): # if the response is a 0, then it was a negative acknowledgement, not received
                    print("\nNAK received\n") # need to re send packet
            
        
    def rdt_2_1_receive(self):
        ret_S = None # return message I think
        byte_S = self.network.udt_receive() # receive a packet from the network
        self.byte_buffer += byte_S # increment the byte buffer by the packet?

        while True: # continue extracting packets
            if len(self.byte_buffer) < Packet.length_S_length: # if we have not received enough bytes to fill the bugger
                break  # not enough bytes to read packet length
            length = int(self.byte_buffer[:Packet.length_S_length]) # length of the packet?
            if len(self.byte_buffer) < length: # if we still have not received enough bytes to fill the buffer
                break  # not enough bytes to read the whole packet
            if Packet.corrupt(self.byte_buffer): # if the packet is corrupt
                print("\nPacket Corrupted\n") # print corruption message
                print("\nNAK\n")
                p = Packet(self.seq_num, '0') # create a packet with a 0, for a negative acknowledgement
                self.network.udt_send(p.get_byte_S()) # send the NAK packet
            else: # if the packet is not corrupted
                rcvpkt = Packet.from_byte_S(self.byte_buffer[0:length]) # create a packet from the buffer
                if rcvpkt.msg_V == '1' or rcvpkt.msg_V == '0': # if the packet is an ACK or NAK
                    self.byte_buffer = self.byte_buffer[length:] # not sure what this does
                    continue
                if rcvpkt.seq_num < self.seq_num: # if the packets sequence number is less than the current sequence number
                    print("\nDuplicate, ACK\n") # there was a duplicate, or a retransmitted packet I think
                    ack = Packet(rcvpkt.seq_num, '1') # create an ACK packet and set to 1
                    self.network.udt_send(rcvpkt.get_byte_S()) # shouldn't this be an ACK...?
                elif rcvpkt.seq_num == self.seq_num: # if the sequence number of the packet is the same as the current sequence number
                    print("\nACK\n") # print acknowledgement message
                    ack = Packet(self.seq_num, '1') # create an ACK packet
                    self.network.udt_send(ack.get_byte_S()) # send the ACK package
                    self.seq_num += 1 # increment the sequence number in preparation for the next transmission
                    break

                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S # add message to the return string
            self.byte_buffer = self.byte_buffer[length:] # empty out buffer
        return ret_S
    
    def rdt_3_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        
        # send packet
        self.network.udt_send(p.get_byte_S())
        # receive packet back
        
        # check for corruption in received packet? Should be an ACK?
        
    def rdt_3_0_receive(self):
        # check for corruption here?
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
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        