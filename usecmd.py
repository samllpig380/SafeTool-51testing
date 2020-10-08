import subprocess
import chardet
from config import config
import time
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



