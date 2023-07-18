# Traffic Analysis Scripts
This repository contains a collection of scripts that I have created for various Forensic projects . Each script is designed to perform a specific task and can be used independently or integrated into other projects.

## snort_monitor.py

The script loads Snort rules from a specified file and monitors network traffic for potential intrusion attempts. It then collects and analyzes alerts generated by Snort during the monitoring process.

#### Prerequisites

Before running the script, make sure you have the following:

- Python installed on your system (Python 3.x recommended).
- `pysnort` library installed. You can install it using `pip`:

#### Usage

Replace `"path/to/file.rules"` with the actual path to your Snort rules file.

To run it :
```bash
python3 snort_monitor.py
```

Ensure that you have the necessary permissions to run Snort and access the network interfaces.

## DOS_detection.py

This Python script aims to detect potential Denial of Service (DoS) attacks in a network traffic capture (pcap) file using the `dpkt` library. A DoS attack occurs when an attacker overwhelms a target system with a high volume of traffic or requests, rendering it unable to respond to legitimate users.

#### Usage

1. Ensure that you have installed the required dependencies, including `dpkt`.
2. Save your pcap file as "your_pcap_file.pcap" in the same directory as this script.
3. Run the script using Python:

```
python3 detect_dos.py
```

#### Configuration

The script has one configuration parameter that can be adjusted:

- `max_packets`: Set the maximum number of packets to be considered for DoS detection. This value helps define the threshold for identifying potential DoS attacks. Modify this value according to the specific requirements of your network and potential attack scenarios.

#### Code Explanation

The script reads a pcap file containing network packets and detects potential DoS attacks on a web server (destination port 80, HTTP port). It analyzes each packet in the pcap file and keeps track of the number of packets sent for each connection (identified by source and destination IP addresses).

If the number of packets sent by any connection exceeds the defined `max_packets` threshold, the script identifies it as a potential DoS attack and prints a message indicating the source and destination IPs and the number of packets sent.

Note: The script assumes that the pcap file contains Ethernet, IP, and TCP data for each packet. Ensure that your pcap file conforms to this format for accurate results.

#### Troubleshooting

If you encounter any issues or have questions, feel free to open an issue on the GitHub repository or seek help from the Python community.

Happy analyzing!
