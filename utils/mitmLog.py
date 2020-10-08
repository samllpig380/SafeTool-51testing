import logging, time
import logging.handlers
import os
LOG_PATH = os.path.join(os.getcwd(),'log\\')
rq = time.strftime('%Y%m%d', time.localtime(time.time()))
class Log(object):
    def __init__(self, name):    
        self.path = LOG_PATH # 定义日志存放路径
        self.filename = self.path + rq + '.log'    # 日志文件名称
        self.name = name    # 为%(name)s赋值
        self.logger = logging.getLogger(self.name)    
        #控制日志文件中记录级别    
        self.logger.setLevel(logging.INFO)    
        #控制输出到控制台日志格式、级别    
        self.ch = logging.StreamHandler()    
        gs = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s[line:%(lineno)d] - %(message)s')    
        self.ch.setFormatter(gs)    
        #日志保留10天,一天保存一个文件    
        self.fh = logging.handlers.TimedRotatingFileHandler(self.filename, 'D', 1, 10)    
        #定义日志文件中格式
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s -   %(name)s[line:%(lineno)d] - %(message)s')
        self.fh.setFormatter(self.formatter)
        self.logger.addHandler(self.fh)
        self.logger.addHandler(self.ch)
    def getlogger(self):
        return self.logger

