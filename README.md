# ScapRoxy
A python scapy proxy

## Requirements
apt-get install build-essential python-dev libnetfilter-queue-dev
pip install NetfilterQueue

## Usage

'Usage: scapROXy.py -a 1 -s 500 -p 8080,3128

Options:
-a n   --attack-mode=n        - Mode of attack
-e     --evil                 - Set the Evil bit
-h     --help                 - This usage screen
-v     --verbose              - Print verbose output
-s n   --packet-size=n        - Packet fragment size (Default: 53)
-p n   --proxy=n              - Add comma seperated ports to firewall rules

Attack modes:
1 - Fragmented
2 - Fragmented and mixed (in development)'
