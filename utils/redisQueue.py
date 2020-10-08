#!/usr/bin/env python
# -*- coding:utf-8 -*-
import redis 

class RedisQueue(object):
    def __init__(self,name,namespace='queue',**redis_kwargs):
        #redis默认参数:host=localhost port=6379 db=0
        self.__db = redis.Redis(**redis_kwargs)
        self.key = '%s:%s'%(namespace,name)
    def qsize(self):
        return self.__db.llen(self.key)#返回队列里面的元素数量

    def put(self,item):
        self.__db.rpush(self.key,item)
    
    def get_wait(self,timeout=None):
        #返回队列的第一个元素，如果为空则等待至有元素加入队列，timeout为None则一致等待
        item = self.__db.blpop(self.key,timeout=timeout)
        return item
    
    def get(self):
        #直接返回第一个元素，没有则返回None
        item = self.__db.lpop(self.key)
        return item
    def flush_all(self):
        self.__db.flushall()
    