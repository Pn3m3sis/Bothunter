Bothunter.py

Info:
This script looks for IoT botnet traffic in PCAP files. It assembles packet streams, makes them searchable then uses regex search parameters to match against known IoT botnet traffic patterns. Matches are labeled with metadata, network information and is saved in a JSON file for easy querying. 

How to use:
Bothunter takes a pcap file as an argument. It will produce a file with the base name of the given file followed by "_bot_traffic.json". Using pypy instead of python will make processing files significantly faster.

python bothunter.py filename.pcap

Dependencies:
Scapy  (pip install scapy)
