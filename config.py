#!/usr/bin/env python
# -*- coding:utf-8 -*-
import yaml
import os
import re
class config:
    def __init__(self):
        path = os.path.dirname(__file__)
        self.yamlPath = path + os.path.sep + "config" + os.path.sep + "mitm.yaml"
        rFile = open(self.yamlPath,'r',encoding='utf-8')
        content = rFile.read()
        self.conf = yaml.load(content,Loader=yaml.FullLoader)
    def get_filters(self):
        return self.conf['monitor']["filters"]
    def get_resp(self):
        return self.conf['monitor']['resp']
    def set_filters(self,values:list):
        self.conf['monitor']["filters"] = values
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)
    def set_resp(self,resp:bool):
        self.conf['monitor']['resp'] = resp
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)
    def get_owasp(self):
        return self.conf['owasp']
    def set_owasp_sign(self,sign):
        self.conf['owasp']['sign'] = sign
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)
    def set_owasp_exploit(self,exploit):
        self.conf['owasp']['exploit'] = exploit
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)
    def set_owasp_type(self,otype):
        self.conf['owasp']['type'] = otype
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)        
    def get_owasp_sign(self):
        return self.conf['owasp']['sign']
    def get_owasp_exploit(self):
        return self.conf['owasp']['exploit']
    def get_owasp_type(self):
        return self.conf['owasp']['type']
    def get_exploit(self):
        return self.conf['exploit']
    def set_wireshark_path(self,path):
        self.conf['wireshark']['task_path'] = path
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)
    def get_wireshark_path(self):
        return self.conf['wireshark']['task_path']
    def set_filter_pcap(self,filterPcap):
        self.conf['wireshark']['filter_pcap'] = filterPcap
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)                
    def get_filter_pcap(self):
        return self.conf['wireshark']['filter_pcap']
    def get_interfaces(self):
        return str(self.conf['wireshark']['interfaces'])
    def get_hydra_path(self):
        return self.conf['hydra']['path']
    def set_hydra_path(self,path):
        self.conf['hydra']['path'] = path
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)         
    def get_sqlmap_path(self):
        return self.conf['sqlmap']['path']
    def set_sqlmap_path(self,path):
        self.conf['sqlmap']['path'] = path
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)
    def get_intercept_url(self):
        return self.conf['intercept']['url']
    def set_intercept_url(self,url):
        flag = False
        for u in self.conf['intercept']['url']:
            if u == url:
                flag = True
                break
        if not flag:
            self.conf['intercept']['url'].append(url)
            wFile = open(self.yamlPath,'w',encoding='utf-8')
            yaml.dump(self.conf,wFile)
    def get_intercept_req(self):
        return self.conf['intercept']['req']
    def set_intercept_req(self,req):
        self.conf['intercept']['req'] = req
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)
    def get_intercept_resp(self):
        return self.conf['intercept']['resp']
    def set_intercept_resp(self,resp):
        self.conf['intercept']['resp'] = resp
        wFile = open(self.yamlPath,'w',encoding='utf-8')
        yaml.dump(self.conf,wFile)           

class interceptConfig:
    def __init__(self):
        path = os.path.dirname(__file__)
        self.yamlPath = path + os.path.sep + "config" + os.path.sep + "intercept.yaml"
        rFile = open(self.yamlPath,'r',encoding='utf-8')
        content = rFile.read()
        self.conf = yaml.load(content,Loader=yaml.FullLoader)
    def get_intercept(self):
        return self.conf['intercept']
    def get_intercept_url_req(self,url):
        result = self.conf['intercept']
        for r in result:
            if url == r['url']:
                return r['request']
        return False
    def get_intercept_url_resp(self,url):
        result = self.conf['intercept']
        for r in result:
            if url == r['url']:
                return r['response']
        return False
    def set_intercept_url(self,url):
        flag = False
        wResult = {}
        for i in self.conf['intercept']:
            if url == i['url']:
                flag = True
                break
        if not flag:
            wResult['url'] = url
            wResult['request'] = {"headers":"","params":""}
            wResult['response'] = {"headers":"","params":""}
            self.conf['intercept'].append(wResult)
            wFile = open(self.yamlPath,'w',encoding='utf-8')
            yaml.dump(self.conf,wFile)
    def set_intercept_url_req_headers(self,url,headers):
        flag = False
        wResult = {}
        yamlLen = len(self.conf['intercept'])
        for i in range(yamlLen):
            if url == self.conf['intercept'][i]['url']:
                self.conf['intercept'][i]['request']['headers'] = headers
                wFile = open(self.yamlPath,'w',encoding='utf-8')
                yaml.dump(self.conf,wFile) 
                break       
    def set_intercept_url_req_params(self,url,params):
        flag = False
        wResult = {}
        yamlLen = len(self.conf['intercept'])
        for i in range(yamlLen):
            if url == self.conf['intercept'][i]['url']:
                self.conf['intercept'][i]['request']['params'] = params
                wFile = open(self.yamlPath,'w',encoding='utf-8')
                yaml.dump(self.conf,wFile) 
                break        
    def set_intercept_url_resp_headers(self,url,headers):
        flag = False
        wResult = {}
        yamlLen = len(self.conf['intercept'])
        for i in range(yamlLen):
            if url == self.conf['intercept'][i]['url']:
                self.conf['intercept'][i]['response']['headers'] = headers
                wFile = open(self.yamlPath,'w',encoding='utf-8')
                yaml.dump(self.conf,wFile) 
                break       
    def set_intercept_url_resp_params(self,url,params):
        flag = False
        wResult = {}
        yamlLen = len(self.conf['intercept'])
        for i in range(yamlLen):
            if url == self.conf['intercept'][i]['url']:
                self.conf['intercept'][i]['response']['params'] = params
                wFile = open(self.yamlPath,'w',encoding='utf-8')
                yaml.dump(self.conf,wFile) 
                break