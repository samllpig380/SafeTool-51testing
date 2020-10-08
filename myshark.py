#!/usr/bin/env python
# -*- coding:utf-8 -*-
import pyshark
import os
import subprocess
from config import config
conf = config() 
tshark_path = conf.get_wireshark_path()
filter_pcap = conf.get_filter_pcap()
file_save = "./pcap/"
#tshark -D 列出可用的网卡 (Adapter for loopback traffic capture 本地数据包铺货 我这里是9)
class MyShark:
    def __init__(self,tshark_path,os_type="windows",file_save="./pcap/",display_filter="http",interfaces = '2'):
        self.os_type = os_type
        self.file_save = file_save
        self.display_filter = display_filter
        self.interfaces = interfaces
        self.tshark_path = tshark_path
    #启动tshark抓包
    def startUpTshark(self,file_name="test",timeout=100):
        if self.os_type == 'windows':
            command = self.tshark_path+" -i " + self.interfaces + " -F pcap " + "-w "+ self.file_save + file_name + ".pcap "+"-a duration:"+str(timeout)
            return command
    #分析数据包
    def analysisData(self,d_path="./pcap/test.pcap"):
        capture = pyshark.FileCapture(d_path,tshark_path=self.tshark_path,display_filter=self.display_filter)
        return capture
if __name__ == "__main__":
    capture = pyshark.FileCapture("./pcap/test.pcap",tshark_path=tshark_path,display_filter='http.request.method == POST')
    for i in capture:
        print(i)
            

