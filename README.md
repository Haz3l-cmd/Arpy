# ARPY #

![image](https://user-images.githubusercontent.com/91953982/203137527-1197a5c3-7fc6-4953-99ec-1c7b14ceb742.png)

## About ##
This simple program takes advantage of [_ARP_](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) to initiate a denial of service(DOS) on the specified target

## Installation guide
***Note that after running the *requirements.txt*, it should run out of the box. The installation is pretty simple, just copy and paste the command/s below, you may wish to run it in a virtual envinronment, see [here](https://docs.python.org/3/library/venv.html)***

-    `pip3 install -r requirements.txt`

## Example ##

![arpy_cli_censored](https://user-images.githubusercontent.com/91953982/203564837-127731aa-0e6d-417a-bdb1-ae8eeb720ccb.png)
 - Using the command below you can start the scan the network and start the stack
 -     sudo python3 arpy.py -S 192.168.100.0/24 -G 192.168.100.1 -T 25
 - Use the command below if you already know the details and do not need to scan the whole subnet
 -     sudo python3 arpy.py -S 192.168.100.0/24 -G 192.168.100.1 -Tgt 192.168.176
 ---
 ## Additional note  ##
 - If the user modifies the program and enables IP forwarding on his/her respective machine, he/she can sniff on the traffic can do all sorts of [_MITM_](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attacks such as [_DNS_](https://www.cloudflare.com/en-gb/learning/dns/what-is-dns/) [_cache_ _poisoing_](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjkh9mrvMT7AhXIVaQEHalgAiMQFnoECDMQAQ&url=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FDNS_spoofing&usg=AOvVaw3T-lm7Zdd79o3clyYeGV1n)
