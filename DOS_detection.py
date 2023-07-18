import dpkt
import socket

# Set the maximum number of packets to be considered for DoS detection
max_packets = 5000


# Function to detect Denial of Service (DoS) attacks
def dect_DOS(pcap):
    # Initialize a dictionary to store the packet count for each connection
    packet_cnt = {}

    # Iterate through each packet in the pcap file
    for (st, buf) in pcap:
        try:
            # Extract Ethernet, IP, and TCP data from the packet
            eth = dpkt.ethernet.Eternet(buf)  # <-- Should be "dpkt.ethernet.Ethernet(buf)"
            ip = eth.data
            source = socket.inet_ntoa(ip.src)
            dest = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dst_port = tcp.dport

            # Check if the destination port is 80 (HTTP port)
            if dst_port == 80:
                # Create a unique connection identifier (stream) using source and destination IPs
                strm = source + ":" + dest

                # Increment the packet count for this connection, if it already exists in the dictionary
                if packet_cnt.has_key(strm):  # <-- In Python 3, use "if strm in packet_cnt:"
                    packet_cnt[strm] = packet_cnt[strm] + 1
                else:
                    # If the connection does not exist in the dictionary, initialize its count to 1
                    packet_cnt = 1  # <-- Should be "packet_cnt[strm] = 1"
        except:
            # Print an error message if there is a problem processing the packet
            print("there is a problem")

    # Iterate through the dictionary of packet counts for each connection
    for strm in packet_cnt:
        # Get the number of packets sent for this connection
        packet_sent = packet_cnt[strm]

        # Check if the number of packets sent exceeds the maximum threshold
        if packet_sent > max_packets:
            # Split the connection identifier (stream) into source and destination IPs
            source = strm.split(':')[0]
            destination = strm.split(':')[1]

            # Print a message indicating a potential DoS attack from the source to the destination
            print(
                "[+] the host" + source + "attacked the web server" + destination + "by sending him " + packet_sent + " packets")

# Sample usage:
if __name__ == "__main__":
    with open("your_pcap_file.pcap", "rb") as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        detect_DOS(pcap)
