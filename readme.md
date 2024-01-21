# RSTEG implementation in python

This repository contains scripts to simulate TCP file transfer.

If RSTEG choosen, secret file will be sent. Transmision should not be much different and secret payloads shouldnt be detected by any additional software.

### Before execution

Implementation is written for Linux based system using Scapy as library that generates TCP packages.

Linux kernel by default sends RST response for scapy package, so creating custom iptables rule is necessary to whitelist ports.

On server instance use with port 65432, and then use this port as dectination port in client script.
This port will be source port from server responses.

`sudo iptables -A OUTPUT -p tcp --sport 65432 --tcp-flags RST RST -j DROP;`

and on client instance use, as it is used by default as source port in client script

`sudo iptables -A OUTPUT -p tcp --sport 23456 --tcp-flags RST RST -j DROP;`


## Overall idea

Wojciech Mazurczyk, Miłosz Smolarczyk, Krzysztof Szczypiorski in thier work writes:

`The main innovation of RSTEG is to not acknowledge a successfully received packet in order to intentionally invoke retransmission. The retransmitted packet of user data then carries a steganogram in the payload field.`

## Important information

This is not covering every scenario, and it was not trying to. Lot more work is needed to protect code from different cases.

## To run execute following:

`sudo python3 scapy_server.py`

`sudo python3 scapy_client.py`

## Result

Recieved files will be saved in the same directiory with names: output and output_secret


