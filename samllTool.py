#!/usr/bin/env python
# -*- coding:utf-8 -*-
import base64
import subprocess
import chardet
from config import config
def base64_coder(coderStr):
    str_coder = base64.b64encode(coderStr.encode('utf-8'))
    return str_coder.decode('utf-8')

def base64_encoder(encodeStr):
    str_encoder = base64.b64decode(encodeStr).decode("utf-8")
    return str_encoder

def runCmd(cmd):
    res = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
    res.wait()
    return res#返回码、输出、错误、进程号

def killPid(res):
    res.kill()
    
def cmdExec(cmd:str,control):
    conf = config()
    if cmd.startswith("hydra"):
        hydra = conf.get_hydra_path()
        cmd = hydra + cmd
    r = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    while True:
        line = r.stdout.readline()
        if line == b'':
            break
        if type(line) == bytes:
            if chardet.detect(line)["encoding"] == "GB2312":
                line = line.strip().decode('gbk')
            else:
                line = bytes.decode(line,errors='ignore')
        control.AppendText(line + "\n")
#taskill /pid pid
#res = runCmd("D:\\Wireshark\\tshark.exe -i 2 -F pcap -w ./pcap/test.pcap -a duration:100")
#sout,serr = res.communicate()
#print(sout)