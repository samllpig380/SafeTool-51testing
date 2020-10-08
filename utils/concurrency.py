#!/usr/bin/env python
# -*- coding:utf-8 -*-
import multiprocessing
import threading
import time
import datetime

class Concurrency:
    '''
    类的描述：启动并发任务，多进程和多线程模式可选
    @author lys
    @params mode 【0-thread，1-process】 count- 线程或进程数量
    @Time 2017-2-23
    '''
    def __init__(self,func,mode = 1,count = 2,params = []):
        self.mode = mode
        self.func = func
        self.params = params
        if self.mode == 1:
            self.process = []
            self.process_count = count
        elif self.mode == 0:
            self.threads = []
            self.thread_count = count
        else:
            print('')
    #启动并发执行
    def run(self):
        if self.mode == 1:
            self.multi_process(self.func,self.params)
        elif self.mode == 0:
            self.multi_threading(self.func,self.params)
    #多进程方式
    def multi_process(self,func,keyword= []):
        if multiprocessing.cpu_count() >= self.process_count and len(keyword) <= self.process_count:
            for w in keyword:
                self.process.append(multiprocessing.Process(target = func, args = (w,)))
            for p in self.process:
                p.start()
        elif multiprocessing.cpu_count() >= self.process_count and len(keyword) == 1:
            for i in range(self.process_count):
                self.process.append(multiprocessing.Process(target = func, args = (keyword[0],)))
            for p in self.process:
                p.start()
        elif multiprocessing.cpu_count() >= self.process_count and len(keyword) == 0:
            for i in range(self.process_count):
                self.process.append(multiprocessing.Process(target = func))
            for p in self.process:
                p.start()
        else:
            print("当前cpu核数："+str(multiprocessing.cpu_count()))
        if len(keyword) == 0:
            for i in range(self.process_count):
                self.process.append(multiprocessing.Process(target = func))
            for p in self.process:
                p.start()
    #多线程方式
    def multi_threading(self,func,keyword = []):
        if len(keyword)==self.thread_count:
            for w in keyword:
                self.threads.append(threading.Thread(target = func, args = (w,)))
            for t in self.threads:
                t.setDaemon(True)
                t.start()
            for t in self.threads:
                t.join()
        elif len(keyword) < self.thread_count and len(keyword)!=1:
            for w in keyword:
                self.threads.append(threading.Thread(target = func, args = (w,)))
            for t in self.threads:
                t.setDaemon(True)
                t.start()
            for t in self.threads:
                t.join()
        elif len(keyword) == 1:
            for i in range(self.thread_count):
                self.threads.append(threading.Thread(target = func, args = (keyword[0],)))
            for t in self.threads:
                t.setDaemon(True)
                t.start()
            for t in self.threads:
                t.join()
        elif len(keyword) ==0:
            for i in range(self.thread_count):
                self.threads.append(threading.Thread(target = func))
            for t in self.threads:
                t.setDaemon(True)
                t.start()
            for t in self.threads:
                t.join()
        else:
            print('线程设置错误。')
        if len(keyword) == 0:
            for i in range(self.thread_count):
                self.threads.append(threading.Thread(target = func))
            for t in self.threads:
                t.setDaemon(True)
                t.start()
            for t in self.threads:
                t.join()

def worker_3(interval):
    print("worker_3"+datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
    time.sleep(interval)
    print("end worker_3")
def worker_4(interval):
    print("worker_4"+datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
    time.sleep(interval)
    print("end worker_4")
def worker_5():
    print("worker_5"+datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
    print("end worker_5")
def loop(info):
    print('thread %s is running...%s' % (threading.current_thread().name,info))
    n = 0
    while n < 5:
        n = n + 1
        print('thread %s >>> %s' % (threading.current_thread().name, n))
        time.sleep(1)
    print('thread %s ended.' % threading.current_thread().name)
if __name__ == "__main__":
    t = Concurrency(loop,0,5,["1","2"])
    t.run()







