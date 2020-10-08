#!/usr/bin/env python
# -*- coding:utf-8 -*-

import itertools
import requests
#返回条件组合值
def tools_compose(*params):
    result_lists = []
    for i in range(len(params)):
        if type(params[i]) != list:
            print('error')
            return
    result = itertools.product(*params)
    for i in result:
        result_lists.append(i)
    return result_lists
headers = {
'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0',
'Content-Type': 'application/x-www-form-urlencoded'
}
s = requests.session()
s.auth = ('guest','guest')
cookies = requests.cookies.create_cookie("JSESSIONID","0309C8414A1148A49168D313164372DB")
s.cookies.set_cookie(cookies)
url = "http://192.168.59.1/WebGoat/attack?Screen=53&menu=200"
'User=Moe&Resource=Public+Share&SUBMIT=Check+Access'
params = {
    "User":"Larry",
    "Resource":"Account Manager",
    "SUBMIT":"Check Access"
}
class ToolsException(Exception):
    def __init__(self,msg):
        Exception.__init__(self,msg)
class ToolsRequests:
    __headers = {
       'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0',
        'Content-Type': 'application/x-www-form-urlencoded' 
    }
    __url = ""
    __params = {}
    def __init__(self):
        self.__session = requests.session()
    def set_headers(self,headers:dict):
        if not isinstance(headers,dict):
            raise ToolsException("headers is not dict!")
        else:
            self.__headers = headers
            self.__session.headers.update(self.__headers)
    def set_url(self,url):
        self.__url = url
    def get_headers(self):
        return self.__headers
    def set_cookie(self,cookies:dict):
        if not isinstance(cookies,dict):
            raise ToolsException("cookies is not dict!")
        elif ("name" not in cookies) or ("value" not in cookies):
            raise ToolsException("cookies must have name and value !")
        else:
            cookies_s = requests.cookies.create_cookie(cookies["name"],cookies["value"])
            self.__session.cookies.set_cookie(cookies_s)
    def set_params(self,params:dict):
        if not self.is_dict(params):
            raise ToolsException("params is not Dict!")
        else:
            self.__params = params
    def is_dict(self,params):
        if not isinstance(params,dict):
            return False
        else:
            return True
    def send_post(self):
        if self.__url == "" or self.__params == {}:
            raise ToolsException("set_url or set_params must be executed first! ")
        else:
            return self.__session.post(self.__url,self.__params)
    def set_auth(self,authinfo):
        self.__session.auth = authinfo
    def send_get(self):
        if self.__url == "":
            raise ToolsException("set_url or set_params must be executed first! ")
        else:
            return self.__session.get(self.__url)
    def send_get_param(self):
        if self.__url == "" or self.__params == {}:
            raise ToolsException("set_url or set_params must be executed first! ")
        else:
            return self.__session.get(self.__url,params=self.__params)
    def send_custom_post(self,data):
        return self.__session.post(self.__url,data = self.__params)           
if __name__ == "__main__":
    a = [1,2,3]
    b = ['a','c','b']
    c = [a,b]
    result = tools_compose(*c)
    #@print(result[0])
    #s.headers.update(headers)
    #r = s.post(url,data=params)
    #print(r.text.find("Congratulations. You have successfully completed this lesson."))
    try:
        my_req = ToolsRequests()
        my_req.set_headers("error")
    except ToolsException as te:
        print(te.args[0])