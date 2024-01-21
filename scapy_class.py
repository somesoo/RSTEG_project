from scapy.all import * # IP, TCP, send, sr, sniff
from scapy.layers.inet import TCP, IP
import threading
import array
import hashlib
import random


class TCPServer:
    def __init__(self, ip="10.0.2.15", port=65432):
        self.ip = ip
        self.port = port
        self.next_seq = random.randrange(0, 2 ** 32)
        self.received_packets = {}
        self.received_secret = {}
        self.output_file = "output"
        self.output_secret = "output_secret"
        self.file_received = False
        self.exit_flag = threading.Event()
        self.rstegkey = "empty"


    def process_packet(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            seq_number = packet[TCP].seq
            payload = packet[TCP].payload
            print("recvd seq: ", seq_number)
            # calculate IS to find if packet will be retransmited or no.
            recvd_IS = bytes(payload)[-32:]
            IS = hashlib.sha256((self.rstegkey + str(seq_number)+ str(1)).encode()).digest()
            IS2 = hashlib.sha256((self.rstegkey + str(seq_number)+ str(0)).encode()).digest()

            if recvd_IS == IS: 
                # steps when RSTEG
                # discoverd bit for retansmision, saving payload to buffer, not sending ACK
                print("retransmision will happen")
                if (src_ip, src_port, seq_number) not in self.received_packets:
                    self.received_packets[(src_ip, src_port, seq_number)] = payload
                    print(f"Odebrane bez wyslania packet from {src_ip}:{src_port}, Seq: {seq_number}")

            elif recvd_IS == IS2: 
                # steps when normal
                # discovered bit saying it is normal transmision
                print("normal packet, check for fin flag and else")
                if (src_ip, src_port, seq_number) not in self.received_packets:
                    self.next_seq = packet[TCP].ack
                    ack_number = seq_number + len(packet[TCP].payload)
                    ack_packet = IP(dst=src_ip, src=self.ip) / TCP(dport=src_port, sport=self.port, flags="A", ack=ack_number, seq=self.next_seq)
                    send(ack_packet)

                    self.received_packets[(src_ip, src_port, seq_number)] = payload
                    print(f"recieved PSH-ACK packet from {src_ip}:{src_port}, Seq: {seq_number}")

                    # Check for the end-of-file flag ('END_OF_FILE')
                    if packet[TCP].flags & 0x01:
                        self.write_to_file()
                        self.file_received = True
                        self.exit_flag.set()
                else:
                    # IG this part will never happen
                    # it should not happen anytime
                    print("it never happens")
                    self.received_secret[(src_ip, src_port, seq_number)] = payload
                    self.next_seq = packet[TCP].ack
                    ack_number = seq_number + len(packet[TCP].payload)
                    ack_packet = IP(dst=src_ip, src=self.ip) / TCP(dport=src_port, sport=self.port, flags="A", ack=ack_number, seq=self.next_seq)
                    send(ack_packet)
            else:
                # steps when packet has secret payload because no IS is found
                print("secret payload because no IS found")
                if (src_ip, src_port, seq_number) not in self.received_packets:
                    # case if payload is secret but no original payload was recieved
                    # recieving payload and not sending ACK to invoke retransmision
                    self.received_secret[(src_ip, src_port, seq_number)] = payload
                    print("recieved secret but no previous payload, not sending ACK")
                else:
                    # case if secret payload is found and original was recieved
                    # calculating next seq and ack and sending ACK packet
                    # checking if FIN flag to finish transmision
                    print("recieved secret, sending ACK and checking if if FIN")
                    self.received_secret[(src_ip, src_port, seq_number)] = payload
                    self.next_seq = packet[TCP].ack
                    ack_number = seq_number + len(packet[TCP].payload)
                    ack_packet = IP(dst=src_ip, src=self.ip) / TCP(dport=src_port, sport=self.port, flags="A", ack=ack_number, seq=self.next_seq)
                    send(ack_packet)
                    if packet[TCP].flags & 0x01:
                        self.write_to_file()
                        self.file_received = True
                        self.exit_flag.set()


    def write_to_file(self):
        with open(self.output_file, 'wb') as output_file:
            # Sort the received packets based on SEQ numbers
            sorted_packets = sorted(self.received_packets.items(), key=lambda x: x[0][2])
            
            # Write the payload of each packet to the output file
            for _, payload in sorted_packets:
                if type(payload) == Raw:
                    payload_bytes = bytes(payload[Raw].load)[:len(bytes(payload[Raw].load))-32]
                    output_file.write(payload_bytes)

        print(f"File written to {self.output_file}")
        self.received_packets = {}  # Clear the received packets after writing to the file

        with open(self.output_secret, 'wb') as output_secret:
            # Sort the received packets based on SEQ numbers
            sorted_secret = sorted(self.received_secret.items(), key=lambda x: x[0][2])
            
            # Write the payload of each packet to the output file
            for _, payloads in sorted_secret:
                if type(payloads) == Raw:
                    payloads_bytes = bytes(payloads[Raw].load)[:len(bytes(payloads[Raw].load))-34]
                    payloads_bytes = re.sub(b'//*$', b'', payloads_bytes)
                    output_secret.write(payloads_bytes)

        print(f"File written to {self.output_secret}")
        self.received_secret = {}  # Clear the received packets after writing to the file


    def sniff_for_packets(self):
        t = threading.currentThread()
        while not self.exit_flag.is_set():
            # Use the sniff function with a shorter timeout (adjust as needed)
            sniff(prn=self.process_packet, store=0, filter=f"tcp and dst host {self.ip} and port {self.port}", timeout=5)

        print("Thread exiting.")
#        sniff(prn=self.process_packet, store=0, filter=f"tcp and host {self.ip} and port {self.port}")


    def start(self):
        sniff_thread=threading.Thread(target=self.sniff_for_packets)
        sniff_thread.start()

        try:
            self.exit_flag.wait()
        except KeyboardInterrupt:
            pass

        sniff_thread.join()
        


class TCPClient:
    def __init__(self, target_ip, target_port, file_path, secret_path):
        self.target_ip = target_ip
        self.target_port = target_port
        self.file_path = file_path
        self.file_chunks= self.read_file()
        if secret_path != None:
            self.secret_path = secret_path
            self.secret_file_chunks = self.read_secret()
        self.next_seq = random.randrange(0, 2 ** 32)
        self.next_ack = 0
        self.timeout = 0.3
        self.rstegkey = "empty"


    def send_large_file(self):
        with open(self.file_path, "rb") as file:
            file_content = file.read()
        chunk_size = 1024
        file_chunks = [file_content[i:i + chunk_size] for i in range(0, len(file_content), chunk_size)]
        for index, chunk in enumerate(file_chunks):
            is_last_packet = index == len(file_chunks) - 1
            flags = "FA" if is_last_packet else "PA"
            IS2 = hashlib.sha256((self.rstegkey + str(self.next_seq)+ str(0)).encode()).digest()
            chunkis = chunk + IS2
            tcp_packet = IP(dst=self.target_ip) / TCP(dport=self.target_port, sport=23456, flags=flags, seq=self.next_seq, ack=self.next_ack) / chunkis
            response, noresponse = sr(tcp_packet, timeout=self.timeout)
            if response and response[0][1][TCP].flags & 0x10:  # Check for ACK flag
                for send, recievef in response:
                    self.next_seq = recievef.getlayer(TCP).ack
                    self.next_ack = recievef.getlayer(TCP).seq
            else:
                print("Failed to receive ACK. Retransmitting...")
                response, noresponse = sr(tcp_packet, timeout=self.timeout)
                if response and response[0][1][TCP].flags & 0x10:  # Check for ACK flag
                    for send, recievef in response:
                        self.next_seq = recievef.getlayer(TCP).ack
                        self.next_ack = recievef.getlayer(TCP).seq


    def calculate_chksum(self, payload, secret_payload):
        # finding diffr that appended to secret payload will give thesame checksum as original one
        if len(payload) % 2 == 1:
            payload += b"\0"
        if len(secret_payload) % 2 == 1:
            secret_payload += b"\0"
        pload = sum(array.array("H", payload))  # sum payload 16bit words
        spload = sum(array.array("H", secret_payload))  # sum secret 16bit words
        diffr = pload - spload  # subtract sums
        diffr = (diffr >> 16) + (diffr & 0xffff)  # shift and mask 16bit for carry
        diffr += diffr >> 16  # make it unsigned
        return diffr
    

    def return_secret_payload(self, chunkis):
        # checks if still has secret payload to send, ajust it length and calculate diffr to match checksum with original packet
        if len(self.secret_file_chunks) > 0:
            secret_payload = self.secret_file_chunks[0].ljust(len(chunkis)-2, b'/')
            self.secret_file_chunks.pop(0)
            diffr = self.calculate_chksum(chunkis, secret_payload)
            diffr = struct.pack('H', diffr)
            secret_payload = secret_payload + diffr
            return secret_payload
        else:
            secret_payload = b"/".ljust(len(chunkis)-2, b'/')
            diffr = self.calculate_chksum(chunkis, secret_payload)
            diffr = struct.pack('H', diffr)
            secret_payload = secret_payload + diffr
            return secret_payload


    def read_file(self):
        # get binary input and split it to chunks that are in size to send in packet
        with open(self.file_path, "rb") as file:
            file_content = file.read()
        chunk_size = 1024
        file_chunks = [file_content[i:i + chunk_size] for i in range(0, len(file_content), chunk_size)]
        return file_chunks
    

    def read_secret(self):
        # get binary input of secret data, and split it to size smaller than default data to leave space for checksum calculation
        with open(self.secret_path, "rb") as file:
            secret_file_content = file.read()
        chunk_size = 1022
        secret_file_chunks = [secret_file_content[i:i + chunk_size] for i in range(0, len(secret_file_content), chunk_size)]
        return secret_file_chunks


    def calculate_retransmision(self, prob):
        # checking if it is able to perform RSTEG or secret data will not be fully transmited
        # it will still be random and data might not be fully delivered
        max_packages = len(self.file_chunks)
        min_packages = len(self.secret_file_chunks)
        if prob < 0 or prob > 100:
            print("RSTEG percentage input not correct.")
            return False
        else:
            if min_packages > (max_packages*prob):
                print("RSTEG input too small.")
                return False
            else:
                return True
            

    def random_rsteg(self, prob):
        random_number = random.randint(0, 99)
        return random_number <= prob


    def send_secret_file(self, prob):
        if self.calculate_retransmision(prob): #calculate if RSTEG is possible to perform.
            for index, chunk in enumerate(self.file_chunks):
                is_last_packet = index == len(self.file_chunks) - 1 #check if transmision will end
                flags = "FA" if is_last_packet else "PA"

                # calculate identyfying sequence
                IS = hashlib.sha256((self.rstegkey + str(self.next_seq)+ str(1)).encode()).digest()
                IS2 = hashlib.sha256((self.rstegkey + str(self.next_seq)+ str(0)).encode()).digest()
                print("seq used to calculate ", self.next_seq)
                if self.random_rsteg(prob) and len(self.secret_file_chunks) > 0:
                    chunkis = chunk + IS
                else:
                    chunkis = chunk + IS2                

                # prepare normal packet
                tcp_packet = IP(dst=self.target_ip) / TCP(dport=self.target_port, sport=23456, flags=flags, seq=self.next_seq, ack=self.next_ack) / chunkis
                del tcp_packet.chksum
                tcp_packet = tcp_packet.__class__(bytes(tcp_packet))

                # send payload with IS or IS2 and wait for ACK
                response = sr1(tcp_packet, timeout=self.timeout)
                if response and response[0][1][TCP].flags & 0x10:  # Check for ACK flag
                    for recievef in response:
                        self.next_seq = recievef.getlayer(TCP).ack
                        self.next_ack = recievef.getlayer(TCP).seq
                        print(f"Normal packet sent, ACK recieved. Next SEQ: {self.next_seq}")
                else:
                    # prepare packet with secret payload
                    secret_payload = self.return_secret_payload(chunkis)               
                    secret_tcp_packet = IP(dst=self.target_ip) / TCP(dport=self.target_port, sport=23456, flags=flags, seq=self.next_seq, ack=self.next_ack) / secret_payload
                    del secret_tcp_packet.chksum
                    secret_tcp_packet = secret_tcp_packet.__class__(bytes(secret_tcp_packet))
                    # check print
                    # print(tcp_packet[TCP].chksum)
                    # print(secret_tcp_packet[TCP].chksum)
                    
                    # send secret payload and wait for ACK
                    print("begin suspicious retransmision, sending secret payload")
                    response2 = sr1(secret_tcp_packet, timeout=self.timeout)
                    if response2 and response2[0][1][TCP].flags & 0x10:  # Check for ACK flag
                        for recievef in response2:
                            self.next_seq = recievef.getlayer(TCP).ack
                            self.next_ack = recievef.getlayer(TCP).seq
                            print(f"Secret packet sent, ACK recieved. Next SEQ: {self.next_seq}")
                    else:
                        # if no ACK after secret payload send normal payload and wait for ACK
                        print("no ACK after secret, sending normal payload one more time")
                        chunkis = chunk + IS2
                        tcp_packet_ret = IP(dst=self.target_ip) / TCP(dport=self.target_port, sport=23456, flags=flags, seq=self.next_seq, ack=self.next_ack) / chunkis
                        response3 = sr1(tcp_packet_ret, timeout=self.timeout)
                        for recievef in response3:
                            self.next_seq = recievef.getlayer(TCP).ack
                            self.next_ack = recievef.getlayer(TCP).seq
                            print(f"Normal packet re-sent, ACK recieved. Next SEQ: {self.next_seq}")
        else:
            self.send_large_file()


