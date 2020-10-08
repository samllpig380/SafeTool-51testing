#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import sys
import wx
from utils.redisQueue import RedisQueue
import json
import _thread as thread
from config import config,interceptConfig
import owaspbreak as owasp
from utils import mitmSql
import samllTool as st
from myshark import MyShark as ms
import replayui as replay
from multiprocessing import Process
from usecmd import cmdExec
import asyncio
from sqlmapui import openSqlmapWindow
import traceback
M_SETUP = 1
M_START = 2
M_STOP = 3
M_CLEAR = 4
P_OWASP = 5
S_Filter = 6
S_RspOpen = 7
O_HTTPBASIC = 8
O_HTTPSPLIT = 9
O_ACM = 10
O_BPATH = 11
O_RBOC = 12
O_RBOC_1 = 13
O_RBOC_2 = 14
O_RBOC_3 = 15
O_RBOC_4 = 16
O_RAA = 17
O_DOM_XSS = 18
O_DOM_Injection = 19
O_ClientSideFlit = 20
O_Same_Origin_Policy = 21
O_XML_Injection = 22
O_JSON_Injection = 23
O_Silent_Transactions_Attacks = 24
O_Insecure_Client_Storage = 25
O_ICSONE = 26
O_ICSTWO = 27
O_Dangerous_Eval = 28
R_OPEN = 29
R_CLOSE = 30
P_OWASP_SECOND = 31
O_Authentication_Flaws = 32
O_Password_Strength = 33
O_Forgot_Password = 34
O_Basic_Authentication = 35
O_Multi_Level_Login_1 = 36
O_MLL1ONE = 37 
O_MLL1TWO = 38
O_Multi_Level_Login_2 = 39
O_Buffer_Overflows = 40
O_Code_Quality = 41
O_Thread_Safety_Problems = 42
O_Shopping_Cart_Concurrency_Flaw = 43
O_Phishing_XSS = 44
O_Stored_XSS = 45
O_FixedStoredXss = 46
O_Reflected_XSS = 47
O_Block_Reflected_XSS = 48
O_Stored_XSS_Attacks = 49
O_Reflected_XSS_Attacks = 50
O_CSRF = 51
O_CSRF_By_Pass = 52
O_CSRF_Token = 53
O_HTTPOnly = 54
O_XST = 55
P_OWASP_THIRD = 56
O_Improper_Error = 57
O_Command_Injection = 58
O_Numeric_SQL_Injection = 59
O_Log_Spoofing = 60
O_XPATH_Injection = 61
O_String_SQL_Injection = 62
O_ParameterizedQuery = 63
O_Numeric_SQL_LAB = 64
O_ParameterizedQuery_Number = 65
O_Modify_Data_SQL_Injection = 66
O_LABSQLInjection = 67
O_Add_Data_SQL_Injection = 68
O_Database_Backdoors = 69
O_Blind_Numeric_SQL_Injection = 70
O_Blind_String_SQL_Injection = 71
O_Denial_of_Service = 72
O_Insecure_Communication = 73
O_Insecure_Configuration = 74
O_Insecure_Storage = 75
O_Malicious_Execution = 76
O_Bypass_HTML_Field_Restrictions = 77
O_Exploit_Hidden_Fields  = 78
O_Exploit_Unchecked_Email = 79
O_Bypass_Client_Side_Validation =80
O_Spoof_Authentication_Cookie = 81
O_Hijack_Session = 82
O_SFONE = 83
O_SFTWO = 84
O_SessionFixation = 85
P_OWASP_FOURTH = 86
O_Create_SOAP_Request = 87
O_WSDL_Scanning = 88
O_Web_Service_SQL_Injection = 89
O_Web_Service_SAX_Injection = 90
P_Challenge = 91
DB_TABLEINFO = 92
DB_FILEDS = 93
DB_SELECT_ALL = 94
DB_RESET_TABLE = 95
ST_CODER = 96
CODER_B64 = 97
ENCODER_B64 = 98
V_Other = 99
V_OWASP = 100
K_ABOUT = 101
ST_WIRESHARK = 102
ST_WS_OPEN = 103
ST_WS_ANALY = 104
ST_WS_CLOSE = 105
POP_COPY = 106
POP_PASTE = 107
HYDRA_HELP = 108
ST_HYDRA = 109
HYDRA_PATH = 110
HYDRA_EXAMPLE = 111
HYDRA_EXEC = 112
SQL_ONE = 113
SQL_TWO = 114
SQL_THREE = 115
SQL_FOUR = 116
SQL_FIVE = 117
SQL_MAP = 118
SQL_SIX = 119
SQL_SEVEN = 120
SQL_EIGHT = 121
SQL_NINE = 122
SQL_TEN = 123
INTERCEPT = 124
INTERCEPT_REQ = 125
INTERCEPT_RESP = 126
INTERCEPT_REQ_OPEN = 127
INTERCEPT_REQ_CLOSE = 128
INTERCEPT_RESP_OPEN = 129
INTERCEPT_RESP_CLOSE = 130
POP_INTERCEPT_REQ_HEADERS = 131
POP_INTERCEPT_REQ_PARAMS = 132
POP_INTERCEPT_RESP_HEADERS = 133
POP_INTERCEPT_RESP_PARAMS = 134
POP_INTERCEPT_REQ = 135
POP_INTERCEPT_RESP = 136
class MainWindow(wx.Frame):
    def __init__(self, parent, id, title):
        wx.Frame.__init__(self, parent, id, title, pos=(10,10),size=(1340,670))
        conf = config()
        respOpen = conf.get_resp()
        interceptReq = conf.get_intercept_req()
        interceptResp = conf.get_intercept_resp()        
        self.sqlmapD = ""
        self.sqlmapT = ""
        self.sqlmapC = ""
        #modify 0823
        self.panel = wx.Panel(self)
        self.rq = RedisQueue("rq")
        self.flag = False
        self.sprocess = ''
        self.Center()#設置彈窗在屏幕中間 
        #控件style=wx.HSCROLL|wx.TE_MULTILINE
        self.control = wx.TextCtrl(self.panel, pos=(5, 35), size=(700, 500), style=wx.NO_BORDER | wx.HSCROLL|wx.TE_MULTILINE)
        self.menuBar = wx.MenuBar()
        self.monitorMenu = wx.Menu()
        self.setUp = wx.Menu()
        self.repOpen = wx.Menu()
        self.setUp.Append(S_Filter,"过滤URL")
        self.open = wx.MenuItem(self.repOpen,R_OPEN,"开启")
        self.close = wx.MenuItem(self.repOpen,R_CLOSE,"关闭")
        if respOpen:
            self.open.Enable(False)
            self.close.Enable(True)
        else:
            self.open.Enable(True)
            self.close.Enable(False)            
        self.repOpen.AppendItem(self.open)
        self.repOpen.AppendItem(self.close)
        self.setUp.AppendMenu(S_RspOpen,"响应开关",self.repOpen)
        self.interceptReq = wx.Menu()
        self.interceptReqOpen = wx.MenuItem(self.interceptReq,INTERCEPT_REQ_OPEN,"开启")
        self.interceptReqClose = wx.MenuItem(self.interceptReq,INTERCEPT_REQ_CLOSE,"关闭")
        if interceptReq:
            self.interceptReqOpen.Enable(False)
            self.interceptReqClose.Enable(True)
        else:
            self.interceptReqOpen.Enable(True)
            self.interceptReqClose.Enable(False)            
        self.interceptReq.AppendItem(self.interceptReqOpen)
        self.interceptReq.AppendItem(self.interceptReqClose)
        self.setUp.AppendMenu(INTERCEPT_REQ,"拦截请求",self.interceptReq)
        self.interceptResp = wx.Menu()
        self.interceptRespOpen = wx.MenuItem(self.interceptResp,INTERCEPT_RESP_OPEN,"开启")
        self.interceptRespClose = wx.MenuItem(self.interceptResp,INTERCEPT_RESP_CLOSE,"关闭")
        if interceptResp:
            self.interceptRespOpen.Enable(False)
            self.interceptRespClose.Enable(True)
        else:
            self.interceptRespOpen.Enable(True)
            self.interceptRespClose.Enable(False)            
        self.interceptResp.AppendItem(self.interceptRespOpen)
        self.interceptResp.AppendItem(self.interceptRespClose)
        self.setUp.AppendMenu(INTERCEPT_REQ,"拦截响应",self.interceptResp)        

        self.start = wx.MenuItem(self.monitorMenu,M_START,"启动")
        self.stop = wx.MenuItem(self.monitorMenu,M_STOP,"停止")
        self.clear = wx.MenuItem(self.monitorMenu,M_CLEAR,"清空")

        self.practiceMenu = wx.Menu()
        self.owaspFirst = wx.Menu()
        self.owaspFirst.Append(O_HTTPBASIC,"HTTP基础知识")
        self.owaspFirst.Append(O_HTTPSPLIT,"HTTP拆分")
        self.owaspFirst.Append(O_ACM,"利用访问控制规则")
        self.owaspFirst.Append(O_BPATH,"绕过基于路径的访问控制")
        self.oRuleBaseAccessControl = wx.Menu()
        self.rbocOne = wx.MenuItem(self.oRuleBaseAccessControl,O_RBOC_1,"课程1")
        self.rbocTwo = wx.MenuItem(self.oRuleBaseAccessControl,O_RBOC_2,"课程2")
        self.rbocThree = wx.MenuItem(self.oRuleBaseAccessControl,O_RBOC_3,"课程3")
        self.rbocFour = wx.MenuItem(self.oRuleBaseAccessControl,O_RBOC_4,"课程4")
        self.oRuleBaseAccessControl.AppendItem(self.rbocOne)
        self.oRuleBaseAccessControl.AppendItem(self.rbocTwo)
        self.oRuleBaseAccessControl.AppendItem(self.rbocThree)
        self.oRuleBaseAccessControl.AppendItem(self.rbocFour)
        self.owaspFirst.AppendMenu(O_RBOC,"基于角色的访问控制",self.oRuleBaseAccessControl)
        self.owaspFirst.Append(O_RAA,"远程管理访问")
        self.owaspFirst.Append(O_DOM_XSS,"基于DOM的跨站脚本攻击")
        self.owaspFirst.Append(O_DOM_Injection,"DOM注入")
        self.owaspFirst.Append(O_ClientSideFlit,"客户端过滤")
        self.owaspFirst.Append(O_Same_Origin_Policy,"同源策略保护")
        self.owaspFirst.Append(O_XML_Injection,"XML注入")
        self.owaspFirst.Append(O_JSON_Injection,"JSON注入")
        self.owaspFirst.Append(O_Silent_Transactions_Attacks,"静默事务攻击")
        self.oInsecureClientStorage = wx.Menu()
        self.icsOne = wx.MenuItem(self.oInsecureClientStorage,O_ICSONE,"课程1")
        self.icsTwo = wx.MenuItem(self.oInsecureClientStorage,O_ICSTWO,"课程2")
        self.owaspFirst.Append(O_Insecure_Client_Storage,"不安全的客户端存储")
        self.owaspFirst.Append(O_Dangerous_Eval,"危险的eval函数")
        self.start.Enable(True)
        self.stop.Enable(False)

        self.owaspSecond = wx.Menu()
        self.AuthenticationFlows = wx.Menu()
        self.PasswordStrength = wx.MenuItem(self.AuthenticationFlows,O_Password_Strength,"密码强度")
        self.ForgotPassword = wx.MenuItem(self.AuthenticationFlows,O_Forgot_Password,"忘记密码功能")
        self.BasicAuthentication = wx.MenuItem(self.AuthenticationFlows,O_Basic_Authentication,"基本认证")
        self.AuthenticationFlows.AppendItem(self.PasswordStrength)
        self.AuthenticationFlows.AppendItem(self.ForgotPassword)
        self.AuthenticationFlows.AppendItem(self.BasicAuthentication)
        self.Multi_Level_Login_1 = wx.MenuItem(self.AuthenticationFlows,O_Multi_Level_Login_1,"多级登录1")
        self.AuthenticationFlows.AppendItem(self.Multi_Level_Login_1)
        self.Multi_Level_Login_2 = wx.MenuItem(self.AuthenticationFlows,O_Multi_Level_Login_2,"多级登录2")
        self.AuthenticationFlows.AppendItem(self.Multi_Level_Login_2)
        self.owaspSecond.AppendMenu(O_Authentication_Flaws,"认证漏洞",self.AuthenticationFlows)
        self.owaspSecond.Append(O_Buffer_Overflows,"缓冲区溢出")
        self.owaspSecond.Append(O_Code_Quality,"敏感信息泄露")
        self.owaspSecond.Append(O_Thread_Safety_Problems,"线程安全")
        self.owaspSecond.Append(O_Shopping_Cart_Concurrency_Flaw,"购物车并发缺陷")
        self.owaspSecond.Append(O_Phishing_XSS,"XSS网络钓鱼漏洞")
        self.owaspSecond.Append(O_Stored_XSS,"存储型Xss")
        self.owaspSecond.Append(O_FixedStoredXss,"修复存储型xss漏洞(开发版)")
        self.owaspSecond.Append(O_Reflected_XSS,"反射型XSS漏洞")
        self.owaspSecond.Append(O_Block_Reflected_XSS,"修复反射型XSS漏洞(开发版)")        
        self.owaspSecond.Append(O_Stored_XSS_Attacks,"存储型XSS攻击")
        self.owaspSecond.Append(O_Reflected_XSS_Attacks,"反射型XSS攻击")
        self.owaspSecond.Append(O_CSRF,"跨站请求伪造(CSRF)")
        self.owaspSecond.Append(O_CSRF_By_Pass,"CSRF旁路攻击(二次确认)")
        self.owaspSecond.Append(O_CSRF_Token,"CSRF令牌绕过")
        self.owaspSecond.Append(O_HTTPOnly,"测试HTTPOnly属性")
        self.owaspSecond.Append(O_XST,"跨站点追踪攻击(XST)")

        self.owaspThird = wx.Menu()
        self.LABSQLInjection = wx.Menu()
        self.StringSQLInjection = wx.MenuItem(self.LABSQLInjection,O_String_SQL_Injection,"字符型SQL注入漏洞")
        self.ParameterizedQuery = wx.MenuItem(self.LABSQLInjection,O_ParameterizedQuery,"字符型SQL解决方案(开发版)")
        self.NumericSQLInjection = wx.MenuItem(self.LABSQLInjection,O_Numeric_SQL_LAB,"数字型SQL注入漏洞")
        self.ParameterizedQueryNumber = wx.MenuItem(self.LABSQLInjection,O_ParameterizedQuery_Number,"数字型SQL解决方案(开发版)")
        self.LABSQLInjection.AppendItem(self.StringSQLInjection)
        self.LABSQLInjection.AppendItem(self.ParameterizedQuery)
        self.LABSQLInjection.AppendItem(self.NumericSQLInjection)        
        self.LABSQLInjection.AppendItem(self.ParameterizedQueryNumber)
        self.owaspThird.Append(O_Improper_Error,"开方式认证方案漏洞")
        self.owaspThird.Append(O_Command_Injection,"命令注入漏洞")
        self.owaspThird.Append(O_Numeric_SQL_Injection,"数字型SQL注入漏洞")
        self.owaspThird.Append(O_Log_Spoofing,"日志欺骗")
        self.owaspThird.Append(O_XPATH_Injection,"XPATH注入漏洞")
        self.owaspThird.AppendMenu(O_LABSQLInjection,"SQL注入实验室",self.LABSQLInjection)
        self.owaspThird.Append(O_Modify_Data_SQL_Injection,"利用SQL注入修改数据")    
        self.owaspThird.Append(O_Add_Data_SQL_Injection,"利用SQL注入增加数据")
        self.owaspThird.Append(O_Database_Backdoors,"利用SQL注入添加后门")
        self.owaspThird.Append(O_Blind_Numeric_SQL_Injection,"数值型SQL盲注")
        self.owaspThird.Append(O_Blind_String_SQL_Injection,"字符型SQL盲注")
        self.owaspThird.Append(O_Denial_of_Service,"拒绝服务漏洞(DOS)")
        self.owaspThird.Append(O_Insecure_Communication,"不安全的通信")
        self.owaspThird.Append(O_Insecure_Configuration,"不安全的配置")
        self.owaspThird.Append(O_Insecure_Storage,"不安全的存储")
        self.owaspThird.Append(O_Malicious_Execution,"恶意文件执行")
        self.owaspThird.Append(O_Bypass_HTML_Field_Restrictions,"绕过html字段限制")
        self.owaspThird.Append(O_Exploit_Hidden_Fields,"利用隐藏字段")
        self.owaspThird.Append(O_Exploit_Unchecked_Email,"利用未校验的电子邮件")
        self.owaspThird.Append(O_Bypass_Client_Side_Validation,"绕过客户端脚本验证")

        self.owaspFourth = wx.Menu()
        self.owaspFourth.Append(O_Spoof_Authentication_Cookie,"伪造身份验证cookie")
        self.owaspFourth.Append(O_Hijack_Session,"会话劫持")
        self.owaspFourth.Append(O_SessionFixation,"会话固定")
        self.owaspFourth.Append(O_Create_SOAP_Request,"创建SOAP请求")
        self.owaspFourth.Append(O_Web_Service_SQL_Injection,"web服务SQL注入漏洞")
        self.owaspFourth.Append(O_Web_Service_SAX_Injection,"web服务SAX注入漏洞")

        self.Challenge = wx.Menu()

        self.monitorMenu = wx.Menu()
        self.monitorMenu.AppendMenu(M_SETUP,"设置",self.setUp)
        self.monitorMenu.AppendItem(self.start)
        self.monitorMenu.AppendItem(self.stop)
        self.monitorMenu.AppendItem(self.clear)
        self.menuBar.Append(self.monitorMenu,"&监控")

        self.mitmDBMenu = wx.Menu()
        self.mitmDBMenu.Append(DB_TABLEINFO,"表信息")
        self.mitmDBMenu.Append(DB_FILEDS,"字段信息")
        self.mitmDBMenu.Append(DB_SELECT_ALL,"查询数据(全部)")
        self.mitmDBMenu.Append(DB_RESET_TABLE,"清空数据")
        self.menuBar.Append(self.mitmDBMenu,"&数据库")

        self.practiceMenu.AppendMenu(P_OWASP,"owasp漏洞_1",self.owaspFirst)
        self.practiceMenu.AppendMenu(P_OWASP_SECOND,"owasp漏洞_2",self.owaspSecond)
        self.practiceMenu.AppendMenu(P_OWASP_THIRD,"owasp漏洞_3",self.owaspThird)
        self.practiceMenu.AppendMenu(P_OWASP_FOURTH,"owasp漏洞_4",self.owaspFourth)
        self.practiceMenu.AppendMenu(P_Challenge,"挑战",self.Challenge)

        self.smallTools = wx.Menu()
        self.coder = wx.Menu()
        self.wireshark = wx.Menu()
        #0830
        self.hydra = wx.Menu()
        self.hydra.Append(HYDRA_HELP,"参数说明")
        self.hydra.Append(HYDRA_PATH,"工具地址(必选)")
        self.hydra.Append(HYDRA_EXAMPLE,"命令示例")
        self.hydra.Append(HYDRA_EXEC,"命令执行")

        self.coder.Append(CODER_B64,"Base64编码")
        self.coder.Append(ENCODER_B64,"Base64解码")
        self.smallTools.AppendMenu(ST_CODER,"编码器",self.coder)
        self.wireshark.Append(ST_WS_OPEN,"开启")
        self.wireshark.Append(ST_WS_ANALY,"分析数据包")
        self.smallTools.AppendMenu(ST_WIRESHARK,"wireshark嗅探器",self.wireshark)
        self.smallTools.AppendMenu(ST_HYDRA,"Hydra破解器",self.hydra)
        self.menuBar.Append(self.practiceMenu,"&演练")
        self.menuBar.Append(self.smallTools,"&小工具")

        self.vulnerabilityLibrary = wx.Menu()
        self.vulnerabilityLibrary.Append(V_OWASP,"OWASP漏洞利用程序")
        self.vulnerabilityLibrary.Append(V_Other,"下个版本实现更多漏洞利用")
        self.menuBar.Append(self.vulnerabilityLibrary,"&漏洞库")

        self.about = wx.Menu()
        self.about.Append(K_ABOUT,"关于")
        self.menuBar.Append(self.about,"&帮助")


        self.SetMenuBar(self.menuBar)
        
        self.control.SetBackgroundColour('Black')
        self.control.SetForegroundColour(wx.GREEN)
        self.sizer2 = wx.BoxSizer(wx.HORIZONTAL)

        self.Bind(wx.EVT_MENU,self.monitor_start_listen_redis_rq,id=M_START)
        self.Bind(wx.EVT_MENU,self.monitor_stop_listen_redis_rq,id=M_STOP)
        self.Bind(wx.EVT_MENU,self.monitor_clear_content,id=M_CLEAR)
        self.Bind(wx.EVT_MENU,self.monitor_set_filter_url,id=S_Filter)
        self.Bind(wx.EVT_MENU,self.monitor_set_resp_open,id=R_OPEN)
        self.Bind(wx.EVT_MENU,self.monitor_set_resp_close,id=R_CLOSE)
        self.Bind(wx.EVT_MENU,self.monitor_set_intercept_req_open,id=INTERCEPT_REQ_OPEN)
        self.Bind(wx.EVT_MENU,self.monitor_set_intercept_req_close,id=INTERCEPT_REQ_CLOSE)
        self.Bind(wx.EVT_MENU,self.monitor_set_intercept_resp_open,id=INTERCEPT_RESP_OPEN)
        self.Bind(wx.EVT_MENU,self.monitor_set_intercept_resp_close,id=INTERCEPT_RESP_CLOSE)
        self.Bind(wx.EVT_MENU,self.db_get_table_info,id=DB_TABLEINFO)
        self.Bind(wx.EVT_MENU,self.db_get_fileds_info,id=DB_FILEDS)
        self.Bind(wx.EVT_MENU,self.db_get_table_data,id=DB_SELECT_ALL)
        self.Bind(wx.EVT_MENU,self.db_reset_table,id=DB_RESET_TABLE)
        self.Bind(wx.EVT_MENU,self.owasp_set_Http_Basics,id=O_HTTPBASIC)
        self.Bind(wx.EVT_MENU,self.owasp_set_HTTP_Splitting,id=O_HTTPSPLIT)
        self.Bind(wx.EVT_MENU,self.owasp_set_Using_an_Access_Control_Matrix,id=O_ACM)
        self.Bind(wx.EVT_MENU,self.owasp_set_Bypass_a_Path_Based_Access_Control,id=O_BPATH)
        self.Bind(wx.EVT_MENU,self.owasp_set_Bypass_Presentational_Layer,id=O_RBOC_1)
        self.Bind(wx.EVT_MENU,self.owasp_set_Add_Business_Layer_Access_Control,id=O_RBOC_2)
        self.Bind(wx.EVT_MENU,self.owasp_set_Breaking_Data_Layer,id=O_RBOC_3)
        self.Bind(wx.EVT_MENU,self.owasp_set_Add_Data_Layer_Access_Control,id=O_RBOC_4)
        self.Bind(wx.EVT_MENU,self.owasp_set_Remote_Admin_Access,id=O_RAA)
        self.Bind(wx.EVT_MENU,self.owasp_set_DOM_Based_xss,id=O_DOM_XSS)
        self.Bind(wx.EVT_MENU,self.owasp_set_DOM_Injection,id=O_DOM_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_Client_Side_Filtering,id=O_ClientSideFlit)
        self.Bind(wx.EVT_MENU,self.owasp_set_Same_Origin_Policy_Protection,id=O_Same_Origin_Policy)
        self.Bind(wx.EVT_MENU,self.owasp_set_xml_injection,id=O_XML_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_json_injection_response,id=O_JSON_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_Silent_Transactions_Attacks,id=O_Silent_Transactions_Attacks)
        self.Bind(wx.EVT_MENU,self.owasp_set_Insecure_Client_Storage,id=O_Insecure_Client_Storage)
        self.Bind(wx.EVT_MENU,self.owasp_set_Dangerous_Use_of_Eval,id=O_Dangerous_Eval)
        self.Bind(wx.EVT_MENU,self.owasp_set_Password_Strength,id=O_Password_Strength)
        self.Bind(wx.EVT_MENU,self.owasp_set_Forgot_Password,id=O_Forgot_Password)
        self.Bind(wx.EVT_MENU,self.owasp_set_Basic_Authentication,id=O_Basic_Authentication)
        self.Bind(wx.EVT_MENU,self.owasp_set_Multi_Level_Login_one,id=O_Multi_Level_Login_1)
        self.Bind(wx.EVT_MENU,self.owasp_set_Multi_Level_Login_two,id=O_Multi_Level_Login_2)
        self.Bind(wx.EVT_MENU,self.owasp_set_Buffer_Overflows,id=O_Buffer_Overflows)
        self.Bind(wx.EVT_MENU,self.owasp_set_Code_Quality,id=O_Code_Quality)
        self.Bind(wx.EVT_MENU,self.owasp_set_Thread_Safety_Problems,id=O_Thread_Safety_Problems)
        self.Bind(wx.EVT_MENU,self.owasp_set_Shopping_Cart_Concurrency_Flaw,id=O_Shopping_Cart_Concurrency_Flaw)
        self.Bind(wx.EVT_MENU,self.owasp_set_Phishing_with_XSS,id=O_Phishing_XSS)
        self.Bind(wx.EVT_MENU,self.owasp_set_Stored_XSS,id=O_Stored_XSS)
        self.Bind(wx.EVT_MENU,self.owasp_set_Block_Stored_XSS,id=O_FixedStoredXss)
        self.Bind(wx.EVT_MENU,self.owasp_set_reflected_xss,id=O_Reflected_XSS)
        self.Bind(wx.EVT_MENU,self.owasp_set_Block_Reflected_XSS,id=O_Block_Reflected_XSS)
        self.Bind(wx.EVT_MENU,self.owasp_set_Stored_XSS_Attacks,id=O_Stored_XSS_Attacks)
        self.Bind(wx.EVT_MENU,self.owasp_set_Reflected_XSS_Attacks,id=O_Reflected_XSS_Attacks)
        self.Bind(wx.EVT_MENU,self.owasp_set_CSRF,id=O_CSRF)
        self.Bind(wx.EVT_MENU,self.owasp_set_CSRF_bypass,id=O_CSRF_By_Pass)
        self.Bind(wx.EVT_MENU,self.owasp_set_CSRF_Token_ByPass,id=O_CSRF_Token)
        self.Bind(wx.EVT_MENU,self.owasp_set_HTTPOnly_Test,id=O_HTTPOnly)
        self.Bind(wx.EVT_MENU,self.owasp_set_Fail_Open_Authentication_Scheme,id=O_Improper_Error)
        self.Bind(wx.EVT_MENU,self.owasp_set_command_injection,id=O_Command_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_number_sql_injection,id=O_Numeric_SQL_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_log_spoofing,id=O_Log_Spoofing)
        self.Bind(wx.EVT_MENU,self.owasp_set_xpath_injection,id=O_XPATH_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_string_sql_injection,id=O_String_SQL_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_Parameterized_Query,id=O_ParameterizedQuery)
        self.Bind(wx.EVT_MENU,self.owasp_set_lab_number_sql_injection,id=O_Numeric_SQL_LAB)
        self.Bind(wx.EVT_MENU,self.owasp_set_Parameterized_Query_number,id=O_ParameterizedQuery_Number)
        self.Bind(wx.EVT_MENU,self.owasp_set_Modify_Data_with_SQL_Injection,id=O_Modify_Data_SQL_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_Add_Data_with_SQL_Injection,id=O_Add_Data_SQL_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_Database_Backdoors,id=O_Database_Backdoors)
        self.Bind(wx.EVT_MENU,self.owasp_set_Improper_Error_Handling,id=O_Improper_Error)
        self.Bind(wx.EVT_MENU,self.owasp_set_Blind_Numeric_SQL_Injection,id=O_Blind_Numeric_SQL_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_Blind_String_SQL_Injection,id=O_Blind_String_SQL_Injection)
        self.Bind(wx.EVT_MENU,self.owasp_set_Insecure_Communication,id=O_Insecure_Communication)
        self.Bind(wx.EVT_MENU,self.owasp_set_Insecure_Configuration,id=O_Insecure_Configuration)
        self.Bind(wx.EVT_MENU,self.owasp_set_Insecure_Storage,id=O_Insecure_Storage)
        self.Bind(wx.EVT_MENU,self.owasp_set_Malicious_Execution,id=O_Malicious_Execution)
        self.Bind(wx.EVT_MENU,self.owasp_set_Bypass_HTML_Field_Restrictions,id=O_Bypass_HTML_Field_Restrictions)
        self.Bind(wx.EVT_MENU,self.owasp_set_Exploit_Hidden_Fields,id=O_Exploit_Hidden_Fields)
        self.Bind(wx.EVT_MENU,self.owasp_set_Exploit_Unchecked_Email,id=O_Exploit_Unchecked_Email)
        self.Bind(wx.EVT_MENU,self.owasp_set_Bypass_Client_Side_JavaScript_Validation,id=O_Bypass_Client_Side_Validation)
        self.Bind(wx.EVT_MENU,self.owasp_set_Spoof_an_Authentication_Cookie,id=O_Spoof_Authentication_Cookie)
        self.Bind(wx.EVT_MENU,self.owasp_set_Hijack_a_Session,id=O_Hijack_Session)
        self.Bind(wx.EVT_MENU,self.owasp_set_Session_Fixation,id=O_SessionFixation)
        self.Bind(wx.EVT_MENU,self.owasp_Create_a_SOAP_Request,id=O_Create_SOAP_Request)



        self.Bind(wx.EVT_MENU,self.samllTools_base64_coder,id=CODER_B64)
        self.Bind(wx.EVT_MENU,self.samllTools_base64_encoder,id=ENCODER_B64)
        self.Bind(wx.EVT_MENU,self.samllTools_wireshark_open,id=ST_WS_OPEN)
        self.Bind(wx.EVT_MENU,self.samllTools_wireshark_analysis,id=ST_WS_ANALY)
        self.Bind(wx.EVT_MENU,self.smallTools_hydra_help,id=HYDRA_HELP)
        self.Bind(wx.EVT_MENU,self.smallTools_hydra_path,id=HYDRA_PATH)
        self.Bind(wx.EVT_MENU,self.smallTools_hydra_example,id=HYDRA_EXAMPLE)
        self.Bind(wx.EVT_MENU,self.smallTools_hydra_exec,id=HYDRA_EXEC)


        self.Bind(wx.EVT_MENU,self.vulnerability_owasp,id=V_OWASP)

        self.Bind(wx.EVT_MENU,self.help_about,id=K_ABOUT)
        #0827
        #self.Bind(wx.EVT_CLOSE,self.onClose)
        # modify 0823
        self.popMenu = wx.Menu()#创建一个菜单
        self.sqlMenu = wx.Menu()
        self.sqlMenu.Append(SQL_ONE,"SQLMAP参数说明")
        self.sqlMenu.Append(SQL_TWO,"SQLMAP使用示例")
        self.sqlMenu.Append(SQL_EIGHT,"创建需求文件")
        self.sqlMenu.Append(SQL_THREE,"检测")
        self.sqlMenu.Append(SQL_FOUR,"猜库")
        self.sqlMenu.Append(SQL_FIVE,"猜表")
        self.sqlMenu.Append(SQL_SIX,"猜列")
        self.sqlMenu.Append(SQL_SEVEN,"猜数据")
        self.sqlMenu.Append(SQL_NINE,"自定义命令定义")
        self.sqlMenu.Append(SQL_TEN,"自定义命令执行")
        self.interceptReqPopMenu = wx.Menu()
        self.interceptReqPopMenu.Append(POP_INTERCEPT_REQ_HEADERS,"头信息")
        self.interceptReqPopMenu.Append(POP_INTERCEPT_REQ_PARAMS,"参数")
        self.interceptRespPopMenu = wx.Menu()
        self.interceptRespPopMenu.Append(POP_INTERCEPT_RESP_HEADERS,"头信息")
        self.interceptRespPopMenu.Append(POP_INTERCEPT_RESP_PARAMS,"参数")
        popMenuList = [u'剪切',u'复制',u'粘贴',u'全选',u'separator',u'重放',u"SQL注入测试",u"修改请求",u"修改响应"]
        for text in popMenuList:#填充菜单
            if text == 'separator':
                self.popMenu.AppendSeparator()
                continue
            if text == "SQL注入测试":
                item = self.popMenu.AppendMenu(SQL_MAP,"SQL注入测试",self.sqlMenu)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_ONE)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_TWO)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_THREE)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_FOUR)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_FIVE)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_SIX)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_SEVEN)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_EIGHT)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_NINE)
                self.Bind(wx.EVT_MENU, self.pop_menu_sqlmap_selected, id = SQL_TEN)
            elif text == "修改请求":
                item = self.popMenu.AppendMenu(POP_INTERCEPT_REQ,"修改请求",self.interceptReqPopMenu)
                self.Bind(wx.EVT_MENU, self.pop_menu_intercept_req_selected, id = POP_INTERCEPT_REQ_HEADERS )
                self.Bind(wx.EVT_MENU, self.pop_menu_intercept_req_selected, id = POP_INTERCEPT_REQ_PARAMS )
            elif text == "修改响应":
                item = self.popMenu.AppendMenu(POP_INTERCEPT_RESP,"修改响应",self.interceptRespPopMenu)
                self.Bind(wx.EVT_MENU, self.pop_menu_intercept_resp_selected, id = POP_INTERCEPT_RESP_HEADERS )
                self.Bind(wx.EVT_MENU, self.pop_menu_intercept_resp_selected, id = POP_INTERCEPT_RESP_PARAMS )
            else:
                item = self.popMenu.Append(-1, text) 
            self.Bind(wx.EVT_MENU, self.pop_menu_item_selected, item) 
            self.panel.Bind(wx.EVT_CONTEXT_MENU, self.pop_menu_on_show)#绑定一个显示菜单事件 
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.control,1,wx.EXPAND)
        self.sizer.Add(self.sizer2,0,wx.EXPAND)
        self.SetSizer(self.sizer)
        self.SetAutoLayout(1)
        #self.SetTransparent(100)
        self.sizer.Fit(self)
        self.Show(True)
    def pop_menu_on_show(self, event):#弹出显示
        pos = event.GetPosition() 
        pos = self.panel.ScreenToClient(pos) 
        self.panel.PopupMenu(self.popMenu, pos) 
    def pop_menu_item_selected(self, event): 
        text = self.popMenu.GetLabel(event.GetId())
        print(event.GetId())
        if text=='剪切': 
            self.control.Cut()
        elif text=='复制': 
            self.control.Copy()
        elif text=='粘贴':
            self.control.Paste()
        elif text=='全选': 
            self.control.SelectAll()
        elif text == '重放':
            self.control.Copy()
            is_success = self.toolGetClipboardText() 
            if is_success:
                p = Process(target=replay.openReplayWindow,args=())
                p.start()
    def pop_menu_sqlmap_selected(self,event):
        eventId = event.GetId()
        if eventId == SQL_ONE:
            content = self.sqlmap_parameter_description()
            p = Process(target=openSqlmapWindow,args=(content,))
            p.start()
        elif eventId == SQL_TWO:
            content = self.sqlmap_use_eg()
            p = Process(target=openSqlmapWindow,args=(content,))
            p.start()
        elif eventId == SQL_THREE:
            self.sqlmap_get_clipboard_text(1)
        elif eventId == SQL_FOUR:
            self.sqlmap_get_clipboard_text(2)
        elif eventId == SQL_FIVE:
            self.sqlmap_get_clipboard_text(3)
        elif eventId == SQL_SIX:
            self.sqlmap_get_clipboard_text(4)
        elif eventId == SQL_SEVEN:
            self.sqlmap_get_clipboard_text(5)
        elif eventId == SQL_EIGHT:
            self.tool_mk_file()
        elif eventId == SQL_NINE:
            self.sqlmap_get_clipboard_text(6)
        elif eventId == SQL_TEN:
            self.sqlmap_get_clipboard_text(7)
    def pop_menu_intercept_req_selected(self,event):
        eventId = event.GetId()
        conf = config()
        req = conf.get_intercept_req()
        if eventId == POP_INTERCEPT_REQ_HEADERS:
            if req:
                msg,url= self.intercept_add_urls()
                if msg == 'success':
                    result = self.tool_input_dialog("以#分割多个头信息，以_分割要替换的属性和值,del和none为删除头信息和置属性值为空")
                    if result:
                        iconf = interceptConfig()
                        iconf.set_intercept_url_req_headers(url,result.strip())
                    else:
                        self.toolMessageDialog("格式不正确或者不能为空")
                else:
                    self.toolMessageDialog(msg)
            else:
                self.toolMessageDialog("需开启拦截功能!")
        elif eventId == POP_INTERCEPT_REQ_PARAMS:
            if req:
                msg,url = self.intercept_add_urls()
                if msg == 'success':
                    result = self.tool_input_dialog("以#分割多个替换值，以_分割要被替换值和替换值,del删除值")
                    if result:
                        iconf = interceptConfig()
                        iconf.set_intercept_url_req_params(url,result.strip())
                    else:
                        self.toolMessageDialog("格式不正确或者不能为空")
                else:
                    self.toolMessageDialog(msg)
            else:
                self.toolMessageDialog("需开启拦截功能!") 
    def pop_menu_intercept_resp_selected(self,event):
        eventId = event.GetId()
        conf = config()
        resp = conf.get_intercept_resp()        
        if eventId == POP_INTERCEPT_RESP_HEADERS:
            if resp:
                msg,url = self.intercept_add_urls()
                if msg == 'success':
                    result = self.tool_input_dialog("以#分割多个头信息，以_分割要替换的属性和值,del和none为删除头信息和置属性值为空")
                    if result:
                        iconf = interceptConfig()
                        iconf.set_intercept_url_resp_headers(url,result.strip())
                    else:
                        self.toolMessageDialog("格式不正确或者不能为空")
                else:
                    self.toolMessageDialog(msg)
            else:
                self.toolMessageDialog("需开启拦截功能!") 
        elif eventId == POP_INTERCEPT_RESP_PARAMS:
            if resp:
                msg,url = self.intercept_add_urls()
                if msg == 'success':
                    result = self.tool_input_dialog("以#分割多个替换值，以_分割要被替换值和替换值,del删除值")
                    if result:
                        iconf = interceptConfig()
                        iconf.set_intercept_url_resp_params(url,result.strip())
                    else:
                        self.toolMessageDialog("格式不正确或者不能为空")
                else:
                    self.toolMessageDialog(msg)
            else:
                self.toolMessageDialog("需开启拦截功能!")              
    def intercept_add_urls(self):
        conf = config()
        iconf = interceptConfig()
        urls = conf.get_intercept_url()
        is_exist = False
        msg = "success"
        if self.start.IsEnabled():
            if urls:
                self.control.Copy()
                textObj = wx.TextDataObject()
                wx.TheClipboard.Open()                
                if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
                    if wx.TheClipboard.GetData(textObj):
                        text = textObj.GetText()
                        text = text.strip()
                        if text.find("http") == 0:
                            for u in urls:
                                if u == text:
                                    is_exist = True
                                    break
                            if not is_exist:
                                conf.set_intercept_url(text)
                                iconf.set_intercept_url(text)
                                return msg,text
                            else:
                                return msg,text
                        else:
                            msg = "请复制要拦截的url完整地址！"
                            return msg,None
                    else:
                        msg = "复制内容为空!"
                        return msg,None
                else:
                    msg = "复制内容为空!"
                    return msg,None
            else:
                msg = "配置文件无拦截选项!"
                return msg,None
        else:
            msg = "请先停止监控!"
            return msg,None
                        

    def sqlmap_parameter_description(self):
        content = '''
        sql支持五种注入模式:
        1 基于布尔的盲注 根据返回值判断条件真假的注入
        2 基于时间的盲注 无法根据返回内容判断,用条件语句查看页面返回时间是否增加,通过时间延迟语句实现
        3 基于报错的注入 通过页面返回错误信息,或者把注入的语句结果直接返回在页面中进行判断
        4 联合查询注入 在语句中包含union的情况下进行注入
        5 堆查询注入 同时执行多条语句的情况下注入
        
        sqlmap支持的数据库有
        MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase和SAP MaxDB

        用法: sqlmap.py [选项]
        1 选项
          -h --help :显示帮助信息
          -hh :显示高级帮助信息
          --version :显示程序版本信息
          -v VERBOSE :VERBOSE的值是0-1,默认是 1
             VERBOSE选项含义 : 0-只显示python错误以及严重的信息
                              1-同时显示基本信息和警告信息
                              2-同时显示debug信息
                              3-同时显示注入的payload
                              4-同时显示HTTP请求
                              5-同时显示HTTP请求头
                              6-同时显示HTTP响应信息

        2 目标 :至少有一个确定目标
          -u URL --url=URL :目标URL
          -d DIRECT :直接连接数据库的连接字符串
          -l LOGFILE : 从 Burp 或者 WebSCarab代理日志文件中分析目标
          -m BULKFILE :将目标地址报错在文件中,一行一个URL地址,批量检测
          -r REQUESTFILE :从文件加载完整的HTTP请求,这样就可以跳过设置一些参数,例如:cookie等头信息
          -g GOOGLEDORK :从谷哥中加载目标URL
          -c CONFIGFILE :从ini(配置文件)中加载选项

        3 请求 :下列选项可以用来指定如何连接到目标URL
          -A AGENT --user-agent=AGENT :设置HTTP请求头中的User-Agent的值,默认的是:sqlmap/1.0-dev-xxxxxxx(http://sqlmap.org)
                                       可以使用此选项进行修改,同时也可以使用--random-agent参数来随机的从./txt/user-agents.txt中获取,
                                       当--level参数设定为3或者3以上的时候，会尝试对User-Angent进行注入.
          -H HEADER :额外的http头(e.g."X-Forwarded-For: 127.0.0.1")
          --method=METHOD :强制使用给定的HTTP方法（例如put）
          --data=DATA :通过POST发送数据参数,sqlmap会像检测GET参数一样检测POST参数
          --param-del=PARA.. :用于拆分参数值的字符(例如: &)
          --cookie=COOKIE : 设置cookie值
          --cookie-del=COO.. :用于拆分cookie的字符(例如: ;)
          --load-cookies=L.. :加载Netscape/wget格式的cookies的文件
          --drop-set-cookie :忽略响应头中的set-cookie选项
          --mobile :通过 HTTP的User-Agent值,模拟智能手机
          --random-agent :使用随机选择的User-Agent
          --host=HOST :设置头信息中的Host值
          --referer=REFERER :设置头信息中的
          --headers=HEADERS :设置额外的有信息(e.g. "Accept-Language: fr\\nETag: 123")
          --auth-type=AUTH.. :HTTP的认证类型(Basic,Digest,NTLM or PKI)
          --auth-cred=AUTH.. :HTTP身份认证凭据(name:password)
          --auth-file=AUTH.. :HTTP认证的PEM证书或私钥文件(web服务端需要客户端证书来验证身份时使用)
          --ignore-code=IG.. :忽略HTTP错误状态码,例如: 401
          --ignore-proxy :忽略系统默认的代理设置
          --ignore-redirects :忽略重定向的尝试
          --ignore-timeouts :忽略连接尝试
          --proxy=PROXY :使用代理连接到目标URL
          --proxy-cred=PRO.. :代理认证凭据(name:password)
          --proxy-file=PRO.. :从文件加载代理列表
          --tor :使用tor网络
          --tor-port=TORPORT :设置tor的代理端口,而不是默认端口
          --tor-type=TORTYPE :设置tor的代理类型(HTTP, SOCKS4 or SOCKS5 (默认))
          --check-tor :检查tor是否能使用
          --delay=DELAY :设定两个http(s)的请求间的延迟,默认无延迟
          --timeout=TIMEOUT :可以设定一个HTTP(S)请求超过多久判定为超时，10表示10秒，默认是30秒
          --retries=RETRIES :连接超时重试次数 ,默认3次 
          --randomize=RPARAM :设定参数值在每次请求的随机变化,长度和类型会和给定的初始值一样
          --safe-url=SAFEURL :提供每隔一段时间都会访问的URL,该URL稳定且不变
          --safe-post=SAFE.. :用于safe-url的post方式提交的参数
          --safe-req=SAFER.. :从文件中加载安全稳定的HTTP请求
          --safe-freq=SAFE.. :有规律的访问安全稳定的HTTP请求
          --skip-urlencode :跳过url编码的载荷数据
          --csrf-token=CSR.. :用来保存使用anti-CSRF令牌数据,绕过csrf保护
          --csrf-url=CSFRURL : 提取anti-CSRF令牌数据的url地址
          --csrf-mehtod=CS.. : 提取anti-CSRF令牌数据使用的HTTP方法
          --csrf-retries=C.. : 重试提取anti-CSRF令牌数据的次数,默认是0
          --force-ssl :强制使用ssl/HTTPS
          --hpp :使用http参数污染的方法
          --eval=EVALCODE :在请求前使用python代码,修改请求参数
                           例子: salmap -u "http://test/vuln.php?id=1&hash=c4c" --eval="import hashlib;hash=hashlib.md5(id).hexdigest()"

          4 优化
          以下选项可以优化sqlmap的性能
          -o :打开所有优化开关
          --predict-output :预测常见的查询输出
          --keep-alive :使用持久HTTP(s)连接
          --null-connection :检索没有实际HTTP响应正文的页长度
          --threads=THREADS :最大并发HTTP请求数（默认为1）

          5 注入
          这些选项可用于指定要测试的参数、提供自定义注入有效负载和可选的篡改脚本
          -p TESTPARAMETER  :可测试的参数
          --skip=SKIP :跳过给定参数的测试
          --skip-static :跳过不显示为动态的参数
          --param-exclude=.. :使用正则表达式排除参数
          --param-filter=P.. :按位置选择可测试参数
          --dbms=DBMS :强制后端的DBMS为此值
          --dbms-cred=DBMS..  :DBMS认证凭证(user:password)
          --os=OS  :强制后端的DBMS操作系统为这个值
          --invalid-bignum :使用大数字使值无效
          --invalid-logical   使用逻辑操作使值无效
          --invalid-string    使用随机字符串使值无效
          --no-cast           关闭有效载荷铸造机制
          --no-escape         关闭字符串逃逸机制
          --prefix=PREFIX     注入payload字符串前缀
          --suffix=SUFFIX     注入payload字符串后缀
          --tamper=TAMPER   使用给定的脚本篡改注入数据,当调用多个脚本时,脚本之间用逗号隔开
          脚本信息:
            apostrophemask.py              用UTF-8全角字符替换单引号字符
            apostrophenullencode.py        用非法双字节unicode字符替换单引号字符
            appendnullbyte.py              在payload末尾添加空字符编码
            base64encode.py                对给定的payload全部字符使用Base64编码
            between.py                     分别用“NOT BETWEEN 0 AND #”替换大于号“>”，“BETWEEN # AND #”替换等于号“=”
            bluecoat.py                    在SQL语句之后用有效的随机空白符替换空格符，随后用“LIKE”替换等于号“=”
            chardoubleencode.py            对给定的payload全部字符使用双重URL编码（不处理已经编码的字符）
            charencode.py                  对给定的payload全部字符使用URL编码（不处理已经编码的字符）
            charunicodeencode.py           对给定的payload的非编码字符使用Unicode URL编码（不处理已经编码的字符）
            concat2concatws.py            用“CONCAT_WS(MID(CHAR(0), 0, 0), A, B)”替换像“CONCAT(A, B)”的实例
            equaltolike.py                用“LIKE”运算符替换全部等于号“=”
            greatest.py                   用“GREATEST”函数替换大于号“>”
            halfversionedmorekeywords.py  在每个关键字之前添加MySQL注释
            ifnull2ifisnull.py            用“IF(ISNULL(A), B, A)”替换像“IFNULL(A, B)”的实例
            lowercase.py                  用小写值替换每个关键字字符
            modsecurityversioned.py       用注释包围完整的查询
            modsecurityzeroversioned.py   用当中带有数字零的注释包围完整的查询
            multiplespaces.py             在SQL关键字周围添加多个空格
            nonrecursivereplacement.py    用representations替换预定义SQL关键字，适用于过滤器
            overlongutf8.py               转换给定的payload当中的所有字符
            percentage.py                 在每个字符之前添加一个百分号
            randomcase.py                 随机转换每个关键字字符的大小写
            randomcomments.py             向SQL关键字中插入随机注释
            securesphere.py               添加经过特殊构造的字符串
            sp_password.py                向payload末尾添加“sp_password” for automatic obfuscation from DBMS logs
            space2comment.py              用“/**/”替换空格符
            space2dash.py                 用破折号注释符“--”其次是一个随机字符串和一个换行符替换空格符
            space2hash.py                 用磅注释符“#”其次是一个随机字符串和一个换行符替换空格符
            space2morehash.py             用磅注释符“#”其次是一个随机字符串和一个换行符替换空格符
            space2mssqlblank.py           用一组有效的备选字符集当中的随机空白符替换空格符
            space2mssqlhash.py            用磅注释符“#”其次是一个换行符替换空格符
            space2mysqlblank.py           用一组有效的备选字符集当中的随机空白符替换空格符
            space2mysqldash.py            用破折号注释符“--”其次是一个换行符替换空格符
            space2plus.py                 用加号“+”替换空格符
            space2randomblank.py          用一组有效的备选字符集当中的随机空白符替换空格符
            unionalltounion.py            用“UNION SELECT”替换“UNION ALL SELECT”
            unmagicquotes.py              用一个多字节组合%bf%27和末尾通用注释一起替换空格符 宽字节注入
            varnish.py                    添加一个HTTP头“X-originating-IP”来绕过WAF
            versionedkeywords.py          用MySQL注释包围每个非函数关键字
            versionedmorekeywords.py      用MySQL注释包围每个关键字
            xforwardedfor.py              添加一个伪造的HTTP头“X-Forwarded-For”来绕过WAF

          6 检测
          以下选项可用于自定义检测阶段,可以用来指定在SQL盲注时如何解析和比较HTTP响应页面的内容
          --level=LEVEL     执行测试的等级（1-5，默认为1）
          --risk=RISK       执行测试的风险（0-3，默认为1）
          --string=STRING    查询时有效时在页面匹配字符串
          --not-string=NOT..  当查询求值为无效时匹配的字符串
          --regexp=REGEXP     查询时有效时在页面匹配正则表达式
          --code=CODE        当查询求值为True时匹配的HTTP代码
          --smart            自动选择执行彻底的测试
          --text-only        仅基于在文本内容比较网页
          --titles           仅根据他们的标题进行比较

          7 技巧
          这些选项可用于调整具体的SQL注入测试
             --technique=TECH    SQL注入技术测试（默认BEUST）
             --time-sec=TIMESEC  DBMS响应的延迟时间（默认为5秒）
             --union-cols=UCOLS  定列范围用于测试UNION查询注入
             --union-char=UCHAR  暴力猜测列的字符数
             --union-from=UFROM  SQL注入UNION查询使用的格式
             --dns-domain=DNS..  DNS泄露攻击使用的域名
             --second-order=S..  URL搜索产生的结果页面 
             --second-url=SEC..  在结果页面搜索二阶响应

          8 指纹
          -f, --fingerprint   执行广泛的DBMS版本指纹检查

          9 枚举
          这些选项可以用来列举后端数据库管理系统的信息、表中的结构和数据。此外，您还可以运行自定义的SQL语句。
            -a, --all           获取所有信息
            -b, --banner        获取数据库管理系统的标识
            --current-user      获取数据库管理系统当前用户
            --current-db        获取数据库管理系统当前数据库
            --hostname         获取数据库服务器的主机名称
            --is-dba            检测DBMS当前用户是否DBA
            --users             枚举数据库管理系统用户
            --passwords         枚举数据库管理系统用户密码哈希
            --privileges        枚举数据库管理系统用户的权限
            --roles            枚举数据库管理系统用户的角色
            --dbs             枚举数据库管理系统数据库
            --tables            枚举的DBMS数据库中的表
            --columns          枚举DBMS数据库表列
            --schema            枚举数据库架构
            --count             检索表的项目数，有时候用户只想获取表中的数据个数而不是具体的内容，那么就可以使用这个参数：sqlmap.py -u url --count -D testdb
            --dump            转储数据库表项
            --dump-all          转储数据库所有表项
            --search           搜索列（S），表（S）和/或数据库名称（S）
            --comments          获取DBMS注释
            -D DB               要进行枚举的指定数据库名
            -T TBL              DBMS数据库表枚举
            -C COL              DBMS数据库表列枚举
            -X EXCLUDECOL     DBMS数据库表不进行枚举
            -U USER           用来进行枚举的数据库用户
            --exclude-sysdbs    枚举表时排除系统数据库
            --pivot-column=P..  Pivot columnname
            --where=DUMPWHERE   Use WHEREcondition while table dumping
            --start=LIMITSTART  获取第一个查询输出数据位置
            --stop=LIMITSTOP   获取最后查询的输出数据
            --first=FIRSTCHAR   第一个查询输出字的字符获取
            --last=LASTCHAR    最后查询的输出字字符获取
            --sql-query=QUERY   要执行的SQL语句
            --sql-shell         提示交互式SQL的shell
            --sql-file=SQLFILE  要执行的SQL文件 

        10 暴力
        这些选项可以被用来运行暴力检查
           --common-tables     检查存在共同表
           --common-columns    检查存在共同列 
           --common-files      检查是否存在公用文件

        11 用户自定义函数注入
        这些选项可以用来创建用户自定义函数
           --udf-inject    注入用户自定义函数
           --shared-lib=SHLIB  共享库的本地路径

        12 访问文件系统
        这些选项可以被用来访问后端数据库管理系统的底层文件系统
        --file-read=RFILE   从后端的数据库管理系统文件系统读取文件
            SQL Server2005中读取二进制文件example.exe:
            sqlmap.py -u"http://testaddress/sqlmap/mssql/iis/get_str2.asp?name=luther"--file-read "C:/example.exe" -v 1
        --file-write=WFILE  编辑后端的数据库管理系统文件系统上的本地文件
        --file-dest=DFILE   后端的数据库管理系统写入文件的绝对路径
            将/software/nc.exe文件上传到C:/WINDOWS/Temp下：
            python sqlmap.py -u"http://testaddress/sqlmap/mysql/get_int.aspx?id=1" --file-write"/software/nc.exe" --file-dest "C:/WINDOWS/Temp/nc.exe" -v1

        13 操作系统访问
        这些选项可以用于访问后端数据库管理系统的底层操作系统
        --os-cmd=OSCMD   执行操作系统命令（OSCMD）
        --os-shell          交互式的操作系统的shell
        --os-pwn          获取一个OOB shell，meterpreter或VNC
        --os-smbrelay       一键获取一个OOBshell，meterpreter或VNC
        --os-bof           存储过程缓冲区溢出利用
        --priv-esc          数据库进程用户权限提升
        --msf-path=MSFPATH  MetasploitFramework本地的安装路径
        --tmp-path=TMPPATH  远程临时文件目录的绝对路径
            linux查看当前用户命令：
            sqlmap.py -u"http://testaddress/sqlmap/pgsql/get_int.php?id=1" --os-cmd id -v1

        14 Windows注册表访问
        这些选项可以被用来访问后端数据库管理系统Windows注册表
        --reg-read          读一个Windows注册表项值
        --reg-add           写一个Windows注册表项值数据
        --reg-del           删除Windows注册表键值
        --reg-key=REGKEY    Windows注册表键
        --reg-value=REGVAL  Windows注册表项值
        --reg-data=REGDATA  Windows注册表键值数据
        --reg-type=REGTYPE  Windows注册表项值类型

        15 常规选项
        这些选项可用于设置一些常规工作参数
        -s SESSIONFILE     保存和恢复检索会话文件的所有数据
        -t TRAFFICFILE      记录所有HTTP流量到一个文本文件中
        --batch            从不询问用户输入，使用所有默认配置。
        --binary-fields=..  结果字段具有二进制值(e.g."digest")
        --charset=CHARSET   强制字符编码
        --crawl=CRAWLDEPTH  从目标URL爬行网站
        --crawl-exclude=..  正则表达式从爬行页中排除
        --csv-del=CSVDEL    限定使用CSV输出 (default",")
        --dump-format=DU..  转储数据格式(CSV(default), HTML or SQLITE)
        --eta              显示每个输出的预计到达时间
        --flush-session     刷新当前目标的会话文件
        --forms           解析和测试目标URL表单
        --fresh-queries     忽略在会话文件中存储的查询结果
        --hex             使用DBMS Hex函数数据检索
        --output-dir=OUT..  自定义输出目录路径
        --parse-errors      解析和显示响应数据库错误信息
        --save=SAVECONFIG   保存选项到INI配置文件
        --scope=SCOPE    从提供的代理日志中使用正则表达式过滤目标
        --test-filter=TE..  选择测试的有效载荷和/或标题(e.g. ROW)
        --test-skip=TEST..  跳过试验载荷和/或标题(e.g.BENCHMARK)
        --update            更新sqlmap

        16 其他：
        这些选项不属于任何其他类别
        -z MNEMONICS        使用短记忆法 (e.g."flu,bat,ban,tec=EU")
        --alert=ALERT       发现SQL注入时，运行主机操作系统命令
        --answers=ANSWERS   当希望sqlmap提出输入时，自动输入自己想要的答案(e.g. "quit=N,follow=N")，例如：sqlmap.py -u"http://192.168.22.128/get_int.php?id=1"--technique=E--answers="extending=N"    --batch
        --beep    发现sql注入时，发出蜂鸣声。
        --cleanup     清除sqlmap注入时在DBMS中产生的udf与表。
        --dependencies      Check formissing (non-core) sqlmap dependencies
        --disable-coloring  默认彩色输出，禁掉彩色输出。
        --gpage=GOOGLEPAGE 使用前100个URL地址作为注入测试，结合此选项，可以指定页面的URL测试
        --identify-waf      进行WAF/IPS/IDS保护测试，目前大约支持30种产品的识别
        --mobile     有时服务端只接收移动端的访问，此时可以设定一个手机的User-Agent来模仿手机登陆。
        --offline           Work inoffline mode (only use session data)
        --purge-output     从输出目录安全删除所有内容，有时需要删除结果文件，而不被恢复，可以使用此参数，原有文件将会被随机的一些文件覆盖。
        --skip-waf           跳过WAF／IPS / IDS启发式检测保护
        --smart            进行积极的启发式测试，快速判断为注入的报错点进行注入
        --sqlmap-shell      互动提示一个sqlmapshell
        --tmp-dir=TMPDIR    用于存储临时文件的本地目录
        --web-root=WEBROOT  Web服务器的文档根目录(e.g."/var/www")
        --wizard   新手用户简单的向导使用，可以一步一步教你如何输入针对目标注入 
                                           
        '''
        return content                        
    def sqlmap_use_eg(self):
        content = '''
        1 get型
          
          1.1 注入检测
          python sqlmap.py -u http://localhost/sqli-labs-master/Less-1/?id=1 --batch
          存在注入点,则执行以下步骤
          
          1.2 获取当前数据库名称
          python sqlmap.py -u "http://localhost/sqli-labs-master/Less-1/?id=1" --current-db

          1.3 获取表名
          python sqlmap.py -u "http://localhost/sqli-labs-master/Less-1/?id=1" -D security --tables 

          1.4 获取列名
          python sqlmap.py -u "http://localhost/sqli-labs-master/Less-1/?id=1" -D security -T users --columns

          1.5 获取字段内容
          python sqlmap.py -u "http://localhost/sqli-labs-master/Less-1/?id=1" -D security -T users -C password --dump
        
        2 post型 

          将http请求保存在txt文件中,格式如下:

            POST /sqli-labs/Less-11/ HTTP/1.1
            Host: localhost
            Connection: keep-alive
            Content-Length: 34
            Cache-Control: max-age=0
            Upgrade-Insecure-Requests: 1
            Origin: http://localhost
            Content-Type: application/x-www-form-urlencoded
            User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
            Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
            Sec-Fetch-Site: same-origin
            Sec-Fetch-Mode: navigate
            Sec-Fetch-User: ?1
            Sec-Fetch-Dest: document
            Referer: http://localhost/sqli-labs/Less-11/
            Accept-Encoding: gzip, deflate, br
            Accept-Language: zh-CN,zh;q=0.9

            uname=user&passwd=pwd&submit=Submit

          保存成req.txt 
                   
          2.1 注入检测
          python sqlmap.py -r req.txt --batch

          2.2 获取当前数据库名称
          python sqlmap.py -r req.txt --current-db

          2.3 获取表名
          python sqlmap.py -r req.txt -D security --tables 

          2.4 获取列表
          python sqlmap.py -r req.txt -D security -T users --columns

          2.5 获取字段内容
          python sqlmap.py -r req.txt -D security -T users -C password --dump
        '''
        return content
    def toolGetClipboardText(self):
        repay_rq = RedisQueue("repayrq")
        textObj = wx.TextDataObject()
        wx.TheClipboard.Open()
        is_flag = True
        if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
            if wx.TheClipboard.GetData(textObj):
                text = textObj.GetText()
                query_result = mitmSql.mitm_select_data_filter("mitmhttp","url",text)
                if query_result:
                    repay_rq.put(json.dumps(query_result[0]))
                else:
                   self.toolMessageDialog("未找到数据!")
                   is_flag = False
            else:
                self.toolMessageDialog("未选中数据!")
                is_flag = False
            wx.TheClipboard.Close()
            return is_flag
    def sqlmap_get_clipboard_text(self,orderType):
        conf = config()
        path = conf.get_sqlmap_path()
        fileName = "\\sqlInj\\r.txt"
        curPath = os.getcwd()
        fileName = curPath + fileName 
        generalOrder =  "python " + path + " -r " + fileName      
        testOrder =  generalOrder + " --batch"
        guessDB = generalOrder + " --current-db"
        if self.start.IsEnabled():
            if orderType == 1 :
                self.control.Copy()
                textObj = wx.TextDataObject()
                wx.TheClipboard.Open()
                is_write = False
                contents = []
                if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
                    if wx.TheClipboard.GetData(textObj):
                        text = textObj.GetText()
                        query_result = mitmSql.mitm_select_data_filter("mitmhttp","url",text)
                        if query_result:
                            for r in query_result:
                                if r["method"] == "GET":
                                    url = r['url'].split(r['system_name'])[1]
                                    one = r["method"] + " " + url + " " + "HTTP/1.1"
                                    contents.append(one)
                                    for k,v in r["headers"].items():
                                        two = k + ": " + v
                                        contents.append(two)
                                elif r["method"] == "POST":
                                    url = r['url'].split(r['system_name'])[1]
                                    one = r["method"] + " " + url + " " + "HTTP/1.1"
                                    contents.append(one)
                                    for k,v in r["headers"].items():
                                        two = k + ": " + v
                                        contents.append(two)
                                    contents.append("")
                                    contents.append(r['params'])                            
                                break
                            self.tool_write_file("#####")
                            for c in contents:
                                self.tool_write_file(c)
                            self.control.Clear()                            
                            thread.start_new_thread(st.cmdExec,(testOrder,self.control))
                        else:
                            self.toolMessageDialog("未找到数据!")
                else:
                    self.toolMessageDialog("未找到数据!") 
            elif orderType == 2:
                self.control.Clear()
                thread.start_new_thread(st.cmdExec,(guessDB,self.control))
            elif orderType == 3:
                dlg = wx.TextEntryDialog(None,u"情输入数据库名称",u"设置",value="")
                dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
                if dlg.ShowModal() == wx.ID_OK:
                    message = dlg.GetValue()
                    if message:
                        self.sqlmapD = message.strip()
                        guessT = generalOrder + " -D " + message.strip() + " --tables"
                        self.control.Clear()
                        thread.start_new_thread(st.cmdExec,(guessT,self.control))
                    else:
                        dlg_tip.ShowModal()
            elif orderType == 4:
                dlg = wx.TextEntryDialog(None,u"情输入数据表名称",u"设置",value="")
                dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
                if dlg.ShowModal() == wx.ID_OK:
                    message = dlg.GetValue()
                    if message:
                        if self.sqlmapD:
                            self.sqlmapT = message.strip()
                            guessC = generalOrder + " -D " + self.sqlmapD + " -T " +  message.strip() + " --columns"
                            self.control.Clear()
                            thread.start_new_thread(st.cmdExec,(guessC,self.control))
                        else:
                            tip = wx.MessageDialog(None, "需先执行猜库!", u"提示信息", wx.OK | wx.ICON_INFORMATION) 
                            tip.ShowModal()   
                    else:
                        dlg_tip.ShowModal() 
            elif  orderType == 5: 
                dlg = wx.TextEntryDialog(None,u"情输入列名称",u"设置",value="")
                dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
                if dlg.ShowModal() == wx.ID_OK:
                    message = dlg.GetValue()
                    if message:
                        if self.sqlmapT:
                            self.sqlmapC = message.strip()
                            guessDt = generalOrder + " -D " + self.sqlmapD + " -T " +  self.sqlmapT + " -C " + message.strip() + " --dump"
                            self.control.Clear()
                            thread.start_new_thread(st.cmdExec,(guessDt,self.control))
                        else:
                            tip = wx.MessageDialog(None, "需先执行猜表!", u"提示信息", wx.OK | wx.ICON_INFORMATION) 
                            tip.ShowModal()  
                    else:
                        dlg_tip.ShowModal()
            elif orderType == 6:
                self.control.Clear()
                self.control.AppendText("请在以下命令后面补充:\n")
                self.control.AppendText("          "+generalOrder + " [补充命令]\n")
            elif orderType == 7:
                self.control.Copy()
                textObj = wx.TextDataObject()
                wx.TheClipboard.Open()
                if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
                    if wx.TheClipboard.GetData(textObj):
                        text = textObj.GetText()
                        self.control.Clear()
                        thread.start_new_thread(st.cmdExec,(text,self.control))                                        
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()                    
    def toolMessageDialog(self,content):
        dlg = wx.MessageDialog(None, content, u"提示信息", wx.YES_NO | wx.ICON_QUESTION)
        if dlg.ShowModal() == wx.ID_YES:
            dlg.Close()
    def tool_write_file(self,content):
        fileName = "\\sqlInj\\r.txt"
        curPath = os.getcwd()
        fileName = curPath + fileName
        try:
            with open(fileName,"a+",encoding="utf-8",errors="ignore") as file_to_write:
                file_to_write.write(content+"\n")
            file_to_write.close()
        except Exception as e:
            print(traceback.print_exc())
            file_to_write.close()
    def tool_mk_file(self):
        fileName = "\\sqlInj\\r.txt"
        curPath = os.getcwd()
        fileName = curPath + fileName
        with open(fileName,"w",encoding="utf-8",errors="ignore") as file_to_write:
            pass
        file_to_write.close()
    def tool_input_dialog(self,tips):
        dlg = wx.TextEntryDialog(None,tips,u"设置",u"")
        if dlg.ShowModal() == wx.ID_OK:
            message = dlg.GetValue()
            if message: 
                message = message.strip()
                if message.find("#") > 0 or message.find("_") > 0:
                    return message
                else:
                    return False
            else:
                return False
        else:
            return False              
    def monitor_start_listen_redis_rq(self,event):
        self.rq.flush_all()
        self.flag = True
        self.start.Enable(False)
        self.stop.Enable(True)
        thread.start_new_thread(self.monitor_get_info,())
    def monitor_stop_listen_redis_rq(self,event):
        self.flag = False
        self.start.Enable(True)
        self.stop.Enable(False)
        self.rq.flush_all()
    def monitor_clear_content(self,event):
        self.control.Clear()
    def monitor_get_info(self):
        reqSign = "####################请求######################\n"
        sepSign = "##############################################\n"
        rspSign = "####################响应#####################\n"
        while self.flag:
            result = self.rq.get_wait()
            strValue = str(result[1],'utf-8')
            jsonValue = json.loads(strValue)
            if "type" in jsonValue.keys():
                self.control.SetDefaultStyle(wx.TextAttr(wx.BLUE))
                self.control.AppendText(rspSign)
            else:
                self.control.SetDefaultStyle(wx.TextAttr(wx.GREEN))
                self.control.AppendText(reqSign)
            for key,value in jsonValue.items():
                strTemp = str(key)+": "+str(value)
                self.control.AppendText(strTemp+"\n")
            self.control.AppendText(sepSign)
    def monitor_set_filter_url(self,event):
        conf = config()
        dlg = wx.TextEntryDialog(None,u"请输入要监控的地址,多个值用&隔开(例如:127.0.0.1&www.51testing.com)",u"URL设置",u"")
        dlg_tip = wx.MessageDialog(None, "默认只过滤127.0.0.1和localhost", u"提示信息", wx.OK | wx.ICON_INFORMATION)
        if dlg.ShowModal() == wx.ID_OK:
            message = dlg.GetValue()
            if message:
                if message.find("&"):
                    values = message.strip().split("&")
                    conf.set_filters(values)
                else:
                    values = []
                    values.append(message.strip())
                    conf.set_filters(values)
            else:
                dlg_tip.ShowModal()
    def monitor_set_resp_open(self,event):
        conf = config()
        conf.set_resp(True)
        self.open.Enable(False)
        self.close.Enable(True)
    def monitor_set_resp_close(self,event):
        conf = config()
        conf.set_resp(False)
        self.open.Enable(True)
        self.close.Enable(False)
    def monitor_set_intercept_req_open(self,event):
        conf = config()
        conf.set_intercept_req(True)
        self.interceptReqOpen.Enable(False)
        self.interceptReqClose.Enable(True)
    def monitor_set_intercept_req_close(self,event):
        conf = config()
        conf.set_intercept_req(False)
        self.interceptReqOpen.Enable(True)
        self.interceptReqClose.Enable(False)
    def monitor_set_intercept_resp_open(self,event):
        conf = config()
        conf.set_intercept_resp(True)
        self.interceptRespOpen.Enable(False)
        self.interceptRespClose.Enable(True)
    def monitor_set_intercept_resp_close(self,event):
        conf = config()
        conf.set_intercept_resp(False)
        self.interceptRespOpen.Enable(True)
        self.interceptRespClose.Enable(False) 
    def help_about(self,event):
        explain = '''
        作者： kail(小猪)
        (此程序会持续更新的功能，最终的目的是囊括大部分漏洞利用程序或测试方法，不局限于web安全测试)
        博客地址：http://quan.51testing.com/pcQuan/owner/482?name=小猪
        历史文章:
        记性能测试经历中的一次疑难问题解决:http://quan.51testing.com/pcQuan/article/144
        记测试生涯中一次安全测试经历:http://quan.51testing.com/pcQuan/article/124
        畅想人工智能如何应用于测试，并写出分析原型:http://quan.51testing.com/pcQuan/lecture/52
        性能测试之师夷长技以自强:http://quan.51testing.com/pcQuan/lecture/8
        安全测试，独孤九剑:http://quan.51testing.com/pcQuan/lecture/64
        入门APP测试之思想框架:http://quan.51testing.com/pcQuan/lecture/72

        '''
        self.owasp_unified_explain(explain)

    def vulnerability_owasp(self,event):
        conf = config()
        exploit = conf.get_exploit()
        line = "\n"
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText("               OWASP漏洞利用程序如下:"+line)
            for e in exploit:
                self.control.AppendText("               "+ e + line)
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()        
    def owasp_set_Http_Basics(self,event):
        explain = '''
            Http_Basics : 课程内容
            +++++++++++++++++++++
            在下面的输入框中输入您的姓名，然后按“go”提交。
            服务器将接受请求，反转输入，并将其显示回用户。
            让大家熟悉下HTTP请求的基本方法。
            用户应该通过操纵上面的按钮来查看提示、
            显示HTTP请求参数、HTTP请求cookies和Java源代码，
            从而熟悉WebGoat的特性。你也可以第一次尝试使用WebScarab。
            教学概念
            本文介绍了理解浏览器与网络应用之间数据传输的基础。
            HTTP的工作原理：
            所有HTTP事务都遵循相同的通用格式。
            每个客户机请求和服务器响应都有三个部分：请求或响应行、头部分和实体。客户按如下方式发起交易：
            客户端联系服务器并发送文档请求
        '''
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def owasp_set_HTTP_Splitting(self,event):
        explain = '''
        HTTP_Splitting : 课程内容
        ++++++++++++++++++++++++
        这一课有两个阶段。第一阶段教你如何进行HTTP拆分攻击，
        而第二阶段则在此基础上教你如何将HTTP拆分提升为缓存中毒。
        输入系统要搜索的语言。您将注意到应用程序正在将您的请求重定向到服务器上的其他资源。
        您应该能够使用CR（%0d）和LF（%0a）字符来攻击。您的目标应该是强制服务器发送200 OK。
        如果屏幕被更改为攻击效果，请返回主页。成功利用第2阶段后，您将在左侧菜单中找到绿色复选框。
        您可能会发现PHP字符集编码器很有用。编码和解码组件按钮转换编码CR和LF。
        '''
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入地址,exploit函数名,类型req或者resp,用#号连接(例如:Screen=55&menu=100#my_exploit_http_split#req)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("#"):
                        sign,exploit,otype = message.strip().split("#") 
                        conf.set_owasp_sign(sign)
                        conf.set_owasp_exploit(exploit)
                        conf.set_owasp_type(otype)
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def owasp_set_Using_an_Access_Control_Matrix(self,event):
        explain = '''
        Using_an_Access_Control_Matrix : 课程内容
        ++++++++++++++++++++++++
        在基于角色的访问控制方案中，角色表示一组访问权限和特权。
        可以为用户分配一个或多个角色。基于角色的访问控制方案通常由两部分组成：角色权限管理和角色分配。
        损坏的基于角色的访问控制方案可能允许用户执行其分配的角色不允许的访问，或者以某种方式允许权限提升到未经授权的角色。
        总体目标：
        每个用户都是只允许访问某些资源的角色的成员。您的目标是探索管理此网站的访问控制规则。只有[管理员]组才可以访问“帐户管理器”资源。
        '''
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入课程地址(例如:Screen=7&menu=200)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("&"):
                        params = message.strip()
                        self.control.AppendText("\n")
                        self.control.SetDefaultStyle(wx.TextAttr(wx.GREEN))
                        result = owasp.my_exploit_Using_an_Access_Control_Matrix(params)
                        if result:
                            self.control.AppendText("可越权访问的用户: " + result["User"] + "\n")
                            self.control.AppendText("管理员账户: " + result["Resource"] + "\n")
                        else:
                            self.control.AppendText("错误信息: 请求访问出错，请清空数据库，重新收集数据!")
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def owasp_set_Bypass_a_Path_Based_Access_Control(self,event):
        explain = '''
        Bypass_a_Path_Based_Access_Control : 课程内容
        ++++++++++++++++++++++++#####################
        “guest”用户有权访问lesson_plans / English目录中的所有文件。
        尝试破坏访问控制机制，并访问不在所列目录中的资源。 
        选择要查看的文件后，WebGoat将报告是否已授予对该文件的访问权限。 
        尝试获取的有趣文件可能是tomcat/conf/tomcat-users.xml之类的文件。 
        请记住，如果使用WebGoat开发版，文件路径将有所不同。
        '''
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入地址,exploit函数名,类型req或者resp,用#号连接(例如:Screen=55&menu=100#my_exploit_http_split#req)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("#"):
                        sign,exploit,otype = message.strip().split("#") 
                        conf.set_owasp_sign(sign)
                        conf.set_owasp_exploit(exploit)
                        conf.set_owasp_type(otype)
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def owasp_set_Bypass_Presentational_Layer(self,event):
        explain = '''
        Bypass Business Layer Access Control : 课程内容
        ++++++++++++++++++++++++#####################
        绕过表示层访问控制。
        作为普通员工“Tom”，利用弱访问控制从员工列表页使用Delete功能。
        确认可以删除Tom的个人资料。
        用户的密码是他们的名字的小写字母（例如，Tom Cat的密码是“Tom”）。
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Breaking_Data_Layer(self,event):
        explain = '''
        Bypass Data Layer Access Control : 课程内容
        ++++++++++++++++++++++++#####################
        第三阶段：破坏数据层访问控制。
        作为普通员工“Tom”，利用弱访问控制查看其他员工的个人资料。验证访问权限。
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Add_Business_Layer_Access_Control(self,event):
        explain = '''
        Add_Business_Layer_Access_Control : 课程内容
        ++++++++++++++++++++++++#####################
        添加应用层控制
        本课程仅适用于WEBGOAT的开发人员版本
        实现一个修复程序来拒绝对该数据的未经授权的访问。完成此操作后，重复步骤2.
        解决方案:
        在org.owasp.webgoat.lessons.RoleBasedAccesControl.RoleBasedAccessControl.java中，
        添加如下代码
        //***************CODE HERE*************************
        if(!isAuthorized(s, getUserId(s), requestedActionName))
        {
        throw new UnauthorizedException();
        }									
        //*************************************************
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Add_Data_Layer_Access_Control(self,event):
        explain = '''
        Add_Data_Layer_Access_Control : 课程内容
        ++++++++++++++++++++++++#####################
        添加数据层访问控制
        本课程仅适用于WEBGOAT的开发人员版本
        实现一个修复程序来拒绝对该数据的未经授权的访问。
        完成此操作后，重复步骤3，并验证是否正确拒绝访问其他员工的配置文件。
        解决方案:
        在org.owasp.webgoat.lessons.RoleBasedAccesControl.RoleBasedAccessControl.java中，添加如下代码
        //***************CODE HERE*************************
        if(!isAuthorized(s, getUserId(s), requestedActionName))
        {
        throw new UnauthorizedException();
        }
        if(!action.isAuthorizedForEmployee(s, getUserId(s), s.getParser().getIntParameter(RoleBasedAccessControl.EMPLOYEE_ID, 0)))
        {
        throw new UnauthorizedException();
        }						
        //*************************************************
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Remote_Admin_Access(self,event):
        explain = '''
        Remote_Admin_Access : 课程内容
        ++++++++++++++++++++++++#####################
        尝试访问WebGoat的管理界面。您还可以尝试访问Tomcat的管理接口.
        解决方案：
        链接地址后加&admin=true，并访问，例如:http://localhost/WebGoat/attack?Screen=35&menu=200&admin=true
        打开菜单"Admin functions"，你将会看到此菜单下多了两个子菜单 "User Information" 和 "Product Information"
        重新点击菜单 “Remote Admin Access”，则完成此课程.
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_DOM_Based_xss(self,event):
        explain = '''
        LAB: DOM-Based cross-site scripting : 课程内容
        ++++++++++++++++++++++++#####################
        实验室：基于DOM的跨站点脚本。
        此实验室共5个考题，通过在每一个阶段输入stage1，stage2，stage3，stage4
        stage5是修复此漏洞，修复方法如下:
        你需要在 (webgoat标准版本)tomcat\webapps\WebGoat\javascript\DOMXSS.js 或者(webgoat开发版本)WebContent\javascript\DOMXSS.js
        修改前:
        function displayGreeting(name) {
        if (name != ''){
        document.getElementById("greeting").innerHTML="Hello, " + name + "!";
        }
        } 
        修改后:
        function displayGreeting(name) {
        if (name != ''){
        document.getElementById("greeting").innerHTML="Hello, " + escapeHTML(name); + "!";
        }
        }               
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_DOM_Injection(self,event):
        explain = '''
        DOM Injection : 课程内容
        ++++++++++++++++++++++++#####################
        DOM注入
        *你的受害者是一个需要激活密钥才能使用的系统。
        *您的目标应该是尝试启用激活按钮。
        *花点时间查看HTML源代码，以便了解密钥验证过程是如何工作的。            
        '''
        self.owasp_unified_exploit(explain)        
    def owasp_set_Client_Side_Filtering(self,event):
        explain = '''
        Client_Side_Filtering : 课程内容
        ++++++++++++++++++++++++#####################
        实验室：客户端筛选
        第一阶段：你是Moe Stooge，山羊山金融的CSO。
        除了首席执行官内维尔•巴塞洛缪（Neville Bartholomew），你可以接触到公司所有人的信息。
        或者至少你不应该接触CEO的信息。对于本练习，请检查页面的内容，以查看可以找到的其他信息。
        解决方案：选择人员后，查询id为hiddenEmployeeRecords的table表格，可以看到Neville Bartholomew的薪水，在输入框中提交即可 
        第二阶段：现在，解决问题。修改服务器以只返回Moe Stooge可以看到的结果。
        此阶段需要在webgoat开发版解决
        eclipse中src/main/webapp/lessons/Ajax/clientSideFiltering.jsp中问题代码如下：

        StringBuffer sb = new StringBuffer();
        sb.append("/Employees/Employee/UserID | ");
        sb.append("/Employees/Employee/FirstName | ");
        sb.append("/Employees/Employee/LastName | ");
        sb.append("/Employees/Employee/SSN | ");
        sb.append("/Employees/Employee/Salary ");
        String expression = sb.toString(); 

        修改成:
        StringBuffer sb = new StringBuffer();
        sb.append("/Employees/Employee[Managers/Manager/text() = " + userId + "]/UserID | ");
        sb.append("/Employees/Employee[Managers/Manager/text() = " + userId + "]/FirstName | ");
        sb.append("/Employees/Employee[Managers/Manager/text() = " + userId + "]/LastName | ");
        sb.append("/Employees/Employee[Managers/Manager/text() = " + userId + "]/SSN | ");
        sb.append("/Employees/Employee[Managers/Manager/text() = " + userId + "]/Salary ");
        String expression = sb.toString();        
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Same_Origin_Policy_Protection(self,event):
        explain = '''
        Same_Origin_Policy_Protection : 课程内容
        ++++++++++++++++++++++++#####################
        这一做法表明了同源政策的保护。XHR请求只能传递回原始服务器。尝试将数据传递到非原始服务器将失败.
        同源策略: 
        举例说明 http://www.51testing.com/bbs 协议://域名地址：端口号，三者相同则为同源，同源则可以相互访问，不同源则不可以交换资源
        此课程主要是演示同源策略，
        先点击lessons/Ajax/sameOrigin.jsp
        再点击http://www.google.com/search?q=aspect+security
        则完成此课程        
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_xml_injection(self,event):
        explain = '''
        xml_injection : 课程内容
        ++++++++++++++++++++++++#####################
        WebGoat Miles奖励里程显示所有可用奖励。
        一旦您输入了您的帐户ID，课程将显示您的余额和您可以负担的产品。
        你的目标是在你允许的奖励中增加更多的奖励。你的帐号是628339。     
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_json_injection_response(self,event):
        explain = '''
        json_injection : 课程内容
        ++++++++++++++++++++++++#####################
        *您将从马萨诸塞州波士顿-机场代码BOS-西雅图-机场代码海。
        *输入机场的三位数代码后，将执行AJAX请求，询问机票价格。
        *你会注意到有两个航班可供选择，一个昂贵的没有停靠站，另一个便宜的有两个停靠站。
        *你的目标是试着以更便宜的价格买到一辆没有停车站的车  
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Silent_Transactions_Attacks(self,event):
        explain = '''
        Silent_Transactions_Attacks : 课程内容
        ++++++++++++++++++++++++#####################
        *这是一个示例网上银行应用程序-汇款页面。
        *它显示在余额下，您要转入的帐户和您将转入的金额。
        *在进行一些基本的客户端验证之后，应用程序使用AJAX提交事务。
        *您的目标是尝试绕过用户的授权并静默执行事务。
        欢迎使用WebGoat银行系统 
        此课程实际上是直接调用客户端的js脚本，已绕过客户端验证.
        解决方案：
        在火狐浏览器的控制台中输入：javascript:submitData(1234556,11000);
        点击回车后，完成此课程。
        '''                
        self.owasp_unified_explain(explain)
    def owasp_set_Insecure_Client_Storage(self,event):
        explain = '''
        Insecure_Client_Storage : 课程内容
        ++++++++++++++++++++++++#####################
        不安全的客户端存储
        阶段1：对于这个练习，您的任务是发现优惠券代码以获得意外折扣。
        阶段2：试着免费得到你的全部订单。

        阶段1解决方案：
        解决此问题，需要设置用火狐浏览器调试客户端的js脚本。
        首先打开火狐浏览器的web开发者功能，切换到调试器窗口，
        在clientSideValidation.js中的
        function isValidCoupon(coupon)的脚本中断点在如下代码行：
        decrypted = decrypt(coupons[i]);PLATINUM
        在页面中输入 Enter your coupon code:，也页面脚本会中断，按F10单步调试，
        并监视decrypted变量的变化，最终得到优惠码 PLATINUM。

        阶段2解决方案：
        不能编辑购物车中的价格。原因是为该字段设置了readonly属性。
        要清除此属性，请打开Firebug。确保这次使用的是HTML视图。
        你可以直接在Firebug中搜索readonly和elemenate属性总计字段称为GRANDTOT。
        从GRANDTOT中删除readonly属性后，可以直接在浏览器中更改价格。
        选择喜欢的任何产品，将total字段更改为0，然后单击“purchase”按钮。

        '''                
        self.owasp_unified_explain(explain)
    def owasp_set_Dangerous_Use_of_Eval(self,explain):
        explain = '''
        Dangerous_Use_of_Eval : 课程内容
        ++++++++++++++++++++++++#####################
        危险的eval函数
        对于这个练习，您的任务是提出一些包含脚本的输入。
        您必须尝试使此页将该输入反映回浏览器，浏览器将执行脚本。
        要通过本课程，你必须弹出当前页面的cookie提示。
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Password_Strength(self,event):
        explain = '''
        Password_Strength : 课程内容
        ++++++++++++++++++++++++#####################
        您的web应用程序的帐户仅与密码相同。
        在本练习中，您的工作是在https://www.cnlab.ch/codecheck上测试几个密码。你必须同时测试所有5个密码。
        将测试的结果填入对应的字段中，点击 go ，则完成此课程。
        此课程的目的实际上就是让使用人员注意密码强度问题，简单的密码很快就能被破解。
        帐户和密码一样安全。
        大多数用户在任何地方都有相同的弱密码。
        如果你想保护他们免受暴力攻击，你的应用程序应该有很好的密码要求。
        密码应包含小写字母、大写字母和数字。密码越长越好。
        答案：
        0
        1394
        5
        2
        41
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Forgot_Password(self,event):
        explain = '''
        Forgot Password : 课程内容
        ++++++++++++++++++++++++#####################
        Web应用程序经常为用户提供检索忘记的密码的能力。不幸的是，许多web应用程序未能正确实现该机制。验证用户身份所需的信息通常过于简单化。
        总体目标：
        如果用户能正确回答这个秘密问题，他们就可以找回密码。此“忘记密码”页上没有锁定机制。
        你的用户名是“webgoat”，你最喜欢的颜色是“红色”。鉴于此来猜测猜测另一个用户的私密问题。
        解决方案：
        输入 admin，分别猜测 red,blue,green

        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Basic_Authentication(self,event):
        explain = '''
        Basic_Authentication : 课程内容
        ++++++++++++++++++++++++#####################
        基于身份的验证
        基本身份验证用于保护服务器端资源。
        web服务器将发送一个401身份验证请求，其中包含对请求的资源的响应。
        然后，客户端浏览器将使用浏览器提供的对话框提示用户输入用户名和密码。
        浏览器将base64编码用户名和密码，并将这些凭据发送回web服务器。
        然后，web服务器将验证凭据，如果凭据正确，则返回请求的资源。
        对于受此机制保护的每个页面，这些凭据都会自动重新发送，而无需用户再次输入其凭据。
        总体目标：
        对于本课，您的目标是了解基本身份验证并回答以下问题。
        验证头的名称是什么：authorization
        认证头的解码值是多少 : guest:guest
        此课程可以通过工具抓包后，分析header中认证字段，解码用小工具的解码器.
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Multi_Level_Login_one(self,event):
        explain = '''
        Multi Level Login 1 : 课程内容
        ++++++++++++++++++++++++#####################
        多级登录
        课程1：这个阶段只是为了展示一个经典的多重登录是如何工作的。你的目标是用密码tarzan以Jane的身份定期登录。你有以下验证码：
        Tan#1=15648
        Tan#2=92156
        Tan#3=4879
        Tan#4=9458
        Tan#5=4879
        第二阶段：现在你是一个黑客，已经通过网络钓鱼邮件从简那里窃取了一些信息。你有密码 tarzan和 验证码15648        
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Multi_Level_Login_two(self,event):
        explain = '''
        Multi Level Login 2 : 课程内容
        ++++++++++++++++++++++++#####################
        多级登录
        你是个叫Joe的袭击者。您有webgoat的有效帐户。你的目标是以Jane的身份登录。你的用户名是Joe，密码是banana。下面是你的验证码： 
        Tan #1 = 15161
        Tan #2 = 4894
        Tan #3 = 18794
        Tan #4 = 1564
        Tan #5 = 45751      
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Buffer_Overflows(self,event):
        explain = '''
        Off-by-One Overflows : 课程内容
        ++++++++++++++++++++++++#####################
        填充溢出
        欢迎来到OWASP酒店！你能知道贵宾住哪个房间吗？
        要访问Internet，您需要向我们提供以下信息：
        步骤1/2
        确保您的名字和姓氏与酒店注册系统中显示的一模一样
        请从以下可用价格计划中选择：
        步骤2/2
        请确保您的选择与使用时间相匹配，因为此服务不会退款。
        解决方案：
        步骤：
        填写所有信息，点击提交
        显示所有隐藏的表单信息，可以使用web developer
        可以看到自己填写的信息
        在room_no字段存在弱点,它不能处理超过4097个字节
        所以在此字段输入超过4097个数字，会显示更多的来宾列表，找到vip用户，填入提交即可。这就是缓冲区溢出造成的数据泄露 
        原理：
        突破浏览器存储的cookie限制，达到溢出的目的，目前ie的cookie的限制是4095个字节。     
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Code_Quality(self,event):
        explain = '''
        Code Quality : 课程内容
        ++++++++++++++++++++++++#####################
        开发人员因留下FIXME、TODO、代码损坏、Hack等语句而臭名昭著。
        在源代码中。检查源代码中是否有任何指示密码、后门或其他不正常工作的注释。
        下面是基于表单的身份验证表单的示例。寻找线索帮助你登录  
        解决方案：
        查看当前页面html源码
        找到注释的代码 用户名admin 密码:adminpw
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Thread_Safety_Problems(self,event):
        explain = '''
        Thread_Safety_Problems : 课程内容
        ++++++++++++++++++++++++#####################
        线程安全问题
        用户应该能够利用此web应用程序中的并发错误，并查看同时尝试相同功能的其他用户的登录信息。这需要使用两个浏览器。有效的用户名是“jeff”和“dave”。
        请输入您的用户名以访问您的帐户。
        解决方案：
        打开两个浏览器，一个输入jeff，一个输入dave，先后点击提交
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Shopping_Cart_Concurrency_Flaw(self,event):
        explain = '''
        Shopping Cart Concurrency Flaw : 课程内容
        ++++++++++++++++++++++++#####################
        购物车并发缺陷
        在这个练习中，您的任务是利用并发问题，这将允许您以较低的价格购买商品。              
        '''
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            reslut = owasp.my_exploit_concurrenc()
            self.control.AppendText("\n")
            self.control.SetDefaultStyle(wx.TextAttr(wx.GREEN))
            self.control.AppendText(reslut)
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def owasp_set_Phishing_with_XSS(self,event):
        explain = '''
        Phishing with XSS : 课程内容
        ++++++++++++++++++++++++#####################
        本课是一个网站如何支持网络钓鱼攻击的示例
        下面是一个标准搜索功能的示例。
        使用XSS和HTML插入，您的目标是：
        将html插入请求凭据
        添加javascript以实际收集凭据
        将凭据发布到http://localhost/webgoat/catcher？PROPERTY=yes
        要通过本课程，必须将凭证发布到 catcher servlet。
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Stored_XSS(self,event):
        explain = '''
        Stored_XSS : 课程内容
        ++++++++++++++++++++++++#####################
        存储型xss
        阶段1：执行存储跨站点脚本（XSS）攻击。
        作为“Tom”，对editprofile页面上的Street字段执行存储的XSS攻击。确认“Jerry”受到攻击的影响。
        帐户的密码是其名字的小写版本（例如，Tom Cat的密码是“Tom”）        
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Block_Stored_XSS(self,event):
        explain = '''
        Block Stored XSS using Input Validation : 课程内容
        ++++++++++++++++++++++++#####################
        使用输入验证阻止存储的XSS
        本课程仅适用于WEBGOAT的开发人员版本
        实现一个修复程序，在存储的XSS写入数据库之前阻止它。
        以“Eric”重复第1阶段，“David”作为经理。确认“David”没有受到攻击的影响.
        解决方案:
        在开发版本的UpdateProfile.java中,填入一下代码:
        /**Your code**/
        String regex = "[\\s\\w-,]*";
        String stringToValidate = firstName+lastName+ssn+title+phone+address1+address2+
        startDate+ccn+disciplinaryActionDate+
        disciplinaryActionNotes+personalDescription;
        Pattern pattern = Pattern.compile(regex);
        validate(stringToValidate, pattern);
        /**End of your code**/      
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_reflected_xss(self,event):
        explain = '''
        Execute a Reflected XSS attack : 课程内容
        ++++++++++++++++++++++++#####################
        使用Search Staff页面上的漏洞来创建包含反射的XSS攻击的URL。
        验证使用链接的另一名员工是否受到攻击的影响。     
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Block_Reflected_XSS(self,event):
        explain = '''
         Block Reflected XSS using Input Validation : 课程内容
        ++++++++++++++++++++++++#####################
        使用输入验证阻止反射的XSS
        本课程仅适用于WEBGOAT的开发人员版本
        实现一个修复来阻止这种反射的XSS攻击。
        重复步骤5。验证攻击URL是否不再有效。
        解决方案:
        修改org.owasp.webgoat.lessons.CrossSiteScripting.FindProfile.java源代码:
        String regex = "[\\s\\w-,]*";
        String parameter = s.getParser().getRawParameter(name);
        Pattern pattern = Pattern.compile(regex);
        validate(parameter, pattern);                
        return parameter;
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Stored_XSS_Attacks(self,event):
        explain = '''
         Stored XSS Attacks : 课程内容
        ++++++++++++++++++++++++#####################
        过滤所有输入总是一个很好的实践，特别是那些稍后将用作操作系统命令、脚本和数据库查询参数的输入。
        尤其是永久存储在应用程序中内容。当检索用户的消息时，用户不应创建可能导致其他用户加载不需要的页面或不需要的内容的消息内容。
        解决方案:
        此阶段和实验室中存储型xss是一样的,只是做了一个简单的应用场景.
        在message字段中填入
        <script language="javascript" type="text/javascript">alert("test");</script>
        点击Submit按钮即可
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Reflected_XSS_Attacks(self,event):
        explain = '''
         Reflected XSS Attacks : 课程内容
        ++++++++++++++++++++++++#####################
        反射型XSS
        在服务器端验证所有输入总是一个很好的实践。
        当在HTTP响应中使用未验证的用户输入时，可能会发生XSS。在反射型XSS攻击中，攻击者可以使用攻击脚本创建一个URL，
        并将其发布到另一个网站、通过电子邮件发送，或者以其他方式让受害者单击它。
        解决方案:
        此阶段和实验中的反射型xss一样,只是做了一个简单的应用场景.
        在Enter your three digit access code:字段中,输入:<script>alert('Bang!')</script>
        点击 Purchase 按钮 提交即可.
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_CSRF(self,event):
        explain = '''
         Cross Site Request Forgery (CSRF) : 课程内容
        ++++++++++++++++++++++++#####################
        跨站点请求伪造
        您的目标是向包含URL指向恶意请求的图像的新闻组发送电子邮件。
        尝试包含包含URL的1x1像素图像。URL应该指向CSRF课程，并附加一个参数“transferFunds=4000”。
        通过右键单击左侧菜单并选择“复制快捷方式”，可以从左侧菜单复制快捷方式。
        无论是谁收到这封电子邮件，并碰巧在那时被认证，他的资金将被转移。
        当你认为攻击成功时，刷新页面，你会在左边的菜单上找到绿色的复选框。
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_CSRF_bypass(self,event):
        explain = '''
         CSRF Prompt By-Pass : 课程内容
        ++++++++++++++++++++++++#####################
        CSRF 旁路(二次确认)
        与CSRF课程类似，您的目标是向包含多个恶意请求的新闻组发送电子邮件：
        第一个请求转移资金，第二个请求确认第一个请求触发的提示。
        URL应该指向CSRF课程，并附加一个参数“transferFunds=4000”和“transferFunds=CONFIRM”。
        通过右键单击左侧菜单并选择“复制快捷方式”，可以从左侧菜单复制快捷方式。
        无论是谁收到这封电子邮件，并碰巧在那时被认证，他的资金将被转移。
        当你认为攻击成功时，刷新页面，你会在左边找到绿色的复选框.
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_CSRF_Token_ByPass(self,event):
        explain = '''
         CSRF Token By-Pass : 课程内容
        ++++++++++++++++++++++++#####################
         CSRF 令牌绕过
         与CSRF课程类似，您的目标是向新闻组发送一封包含恶意转账请求的电子邮件。
         要成功完成，您需要获取有效的请求令牌。显示转移资金表单的页面包含有效的请求令牌。
         转移资金页面的URL与本课相同，并添加了一个额外的参数“transferFunds=main”。
         加载此页面，读取令牌并在伪造的请求中将令牌附加到transferFunds。
         当你认为攻击成功时，刷新页面，你会在左边的菜单上找到绿色的复选框。
         解决方案:
         在message字段中输入:
         <script>
            var tokenvalue;
            function readFrame1()
            {
                var frameDoc = document.getElementById("frame1").contentDocument;
                var form = frameDoc.getElementsByTagName("form")[1];
                var token = form.CSRFToken.value;
                tokenvalue = '&CSRFToken='+token;
                loadFrame2();
            }
            function loadFrame2()
            {
                var testFrame = document.getElementById("frame2");
                testFrame.src="http://localhost:8080/WebGoat/attack?Screen=2&menu=900&transferFunds=4000"+tokenvalue;
            }
            </script>
            <iframe	src="http://localhost:8080/WebGoat/attack?Screen=2&menu=900&transferFunds=main"
                onload="readFrame1();"
                id="frame1" frameborder="1" marginwidth="0"
                marginheight="0" width="800" scrolling=yes height="300"></iframe>
            <iframe id="frame2" frameborder="1" marginwidth="0"
                marginheight="0" width="800" scrolling=yes height="300"></iframe> 
        注意:src字段中的课程地址会变动,按实际结果填入       
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_HTTPOnly_Test(self,event):
        explain = '''
         HTTPOnly Test : 课程内容
        ++++++++++++++++++++++++#####################
        HTTPOnly 属性测试
        为了帮助减轻跨站点脚本的威胁，Microsoft引入了一个名为“HttpOnly”的新cookie属性。
        如果设置了此标志，则浏览器不应允许客户端脚本访问cookie。
        由于属性相对较新，一些浏览器忽略了正确处理新属性。
        有关受支持浏览器的列表，请参阅：OWASP HTTPOnly支持.
        总体目标：
        本课程的目的是测试浏览器是否支持HTTPOnly cookie标志。
        如果您的浏览器支持HTTPOnly，并且您为cookie启用了HTTPOnly，则客户端代码应该无法读写该cookie，但是浏览器仍然可以将其值发送到服务器。
        有些浏览器只阻止客户端的读访问，但不阻止写访问.

        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Cross_Site_Tracing(self,event):
        explain = '''
         Cross_Site_Tracing : 课程内容
        ++++++++++++++++++++++++#####################
        总体目标：
        Tomcat被配置为支持HTTP跟踪命令。
        您的目标是执行跨站点跟踪（XST）攻击。
        XST攻击描述：
        攻击者将恶意代码嵌入一台已经被控制的主机上的web文件，当访问者浏览时恶意代码在浏览器中执行，
        然后访问者的cookie、http基本验证以及ntlm验证信息将被发送到已经被控制的主机，
        同时传送Trace请求给目标主机，导致cookie欺骗或者是中间人攻击。

        XST攻击条件：
        1、需要目标web服务器允许Trace参数；
        2、需要一个用来插入XST代码的地方； 
        3、目标站点存在跨域漏洞。

        XST与XSS的比较:
        相同点：都具有很大的欺骗性，可以对受害主机产生危害，而且这种攻击是多平台多技术的，
        我们还可以利用Active控件、Flash、Java等来进行XST和XSS攻击。
        优点：可以绕过一般的http验证以及NTLM验证
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Fail_Open_Authentication_Scheme(self,event):
        explain = '''
         Fail Open Authentication Scheme : 课程内容
        ++++++++++++++++++++++++#####################
        失败开放式身份验证方案
        由于身份验证机制中的错误处理问题，可以在不输入密码的情况下以“webgoat”用户身份进行身份验证。
        尝试以webgoat用户身份登录而不指定密码。

        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_command_injection(self,event):
        explain = '''
        command_injection : 课程内容
        ++++++++++++++++++++++++#####################
        命令注入
        命令注入攻击对任何参数驱动的站点都是一个严重的威胁。
        攻击背后的方法很容易学习，所造成的损害从相当大的范围到整个系统的损害。
        尽管存在这些风险，但互联网上仍有数量惊人的系统容易受到这种形式的攻击。
        它不仅是一种容易煽动的威胁，而且是一种只要有一点常识和先见之明，几乎可以完全防止的威胁。
        本课将向学生展示几个参数注入的例子。
        过滤所有输入数据，尤其是将在操作系统命令、脚本和数据库查询中使用的数据。
        尝试向操作系统注入命令。
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_number_sql_injection(self,event):
        explain = '''
        number_sql_injection : 课程内容
        ++++++++++++++++++++++++#####################
        数字型sql注入
        SQL注入攻击对任何数据库驱动的站点都是一个严重的威胁。
        攻击背后的方法很容易学习，所造成的损害从相当大的范围到整个系统的损害。
        尽管存在这些风险，但互联网上的数量惊人的系统容易受到这种形式的攻击。
        它不仅是一种容易煽动的威胁，而且是一种只要有一点常识和先见之明，就可以轻易预防的威胁。
        清理所有输入数据，尤其是将在操作系统命令、脚本和数据库查询中使用的数据，这始终是一个好的做法，即使SQL注入的威胁已经通过其他方式得到了防止。
        总体目标：
        下面的表单允许用户查看天气数据。尝试注入一个SQL字符串，该字符串将显示所有天气数据。        
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_log_spoofing(self,event):
        explain = '''
        log_spoofing : 课程内容
        ++++++++++++++++++++++++#####################
        日志欺骗
        *下面的灰色区域表示将要记录在web服务器日志文件中的内容。
        *你的目标是让用户名“admin”成功登录。
        *通过向日志文件中添加脚本来提升攻击。        
        '''
        self.owasp_unified_exploit(explain)

    def owasp_set_xpath_injection(self,event):
        explain = '''
        xpath_injection : 课程内容
        ++++++++++++++++++++++++#####################
        xpath 注入
        下表允许员工查看包括工资在内的所有个人数据。
        你的账号是Mike/test123。
        您的目标是尝试查看其他员工的数据。      
        '''
        self.owasp_unified_exploit(explain)

    def owasp_set_string_sql_injection(self,event):
        explain = '''
        string_sql_injection : 课程内容
        ++++++++++++++++++++++++#####################
        SQL注入攻击对任何数据库驱动的站点都是一个严重的威胁。
        攻击背后的方法很容易学习，所造成的损害从相当大的范围到整个系统的损害。
        尽管存在这些风险，但互联网上的数量惊人的系统容易受到这种形式的攻击。
        它不仅是一种容易煽动的威胁，而且是一种只要有一点常识和先见之明，就可以轻易预防的威胁。
        过滤所有输入数据，尤其是将在操作系统命令、脚本和数据库查询中使用的数据，这始终是一个好的做法，即使SQL注入的威胁已经通过其他方式得到了防止。
        总体目标：
        下面的表单允许用户查看他们的信用卡号码。尝试注入一个SQL字符串，该字符串将显示所有信用卡号码。请尝试用户名“Smith”。      
        '''
        self.owasp_unified_exploit(explain)
        
    def owasp_set_Parameterized_Query(self,event):
        explain = '''
        参数化查询 : 课程内容
        ++++++++++++++++++++++++#####################
        Sql 注入攻击对任何数据库驱动的站点都是严重的威胁。 
        攻击背后的方法很容易学习，造成的损害可以相当大的范围，以完成系统妥协。
        尽管存在这些风险，但互联网上数量惊人的系统，容易受到这种形式的攻击。
        目标：
        该课程需要在webgoat开发版本执行
        在这个练习中，你们将执行 字符型sql注入 攻击。在代码中添加参数查询方法，以防护注入攻击。
        在org.owasp.webgoat.lessons.SQLInjection.Login.java中添加如下代码
        String query = "SELECT employee.* "
            + "FROM employee,ownership WHERE employee.userid = ownership.employee_id and "
            + "ownership.employer_id = ? and ownership.employee_id = ?";
        try
        {
				  Connection connection = WebSession.getConnection(s);
				  PreparedStatement statement = connection.prepareStatement(query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
				  statement.setString(1, userId);
				  statement.setString(2, password);
				  ResultSet answer_results = statement.executeQuery();

        '''
        self.owasp_unified_explain(explain)

    def owasp_set_lab_number_sql_injection(self,event):
        explain = '''
         Lab Numeric SQL Injection : 课程内容
        ++++++++++++++++++++++++#####################
         执行数字型sql注入攻击，并按salary字段排序
        '''        
        self.owasp_unified_exploit(explain)        
    def owasp_set_Parameterized_Query_number(self,event):
        explain = '''
        参数化查询 解决数字型sql注入: 课程内容
        ++++++++++++++++++++++++#####################
        Sql 注入攻击对任何数据库驱动的站点都是严重的威胁。 
        攻击背后的方法很容易学习，造成的损害可以相当大的范围，以完成系统妥协。
        尽管存在这些风险，但互联网上数量惊人的系统，容易受到这种形式的攻击。
        目标：
        该课程需要在webgoat开发版本执行
        在这个练习中，你们将执行 数字型sql注入 攻击。在代码中添加参数查询方法，以防护注入攻击。
        在org.owasp.webgoat.lessons.SQLInjection.ViewProfile.java中的getEmployeeProfile方法中添加如下代码
        String query = "SELECT employee.* "
            + "FROM employee,ownership WHERE employee.userid = ownership.employee_id and "
            + "ownership.employer_id = ? and ownership.employee_id = ?";
        try
        {
        Connection connection = WebSession.getConnections(s);
        PreparedStatement statement = connection.prepareStatement(query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        statement.setString(1, userId);
        statement.setString(2, subjectUserId);
        ResultSet answer_results = statement.executeQuery(); 

        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Modify_Data_with_SQL_Injection(self,event):
        explain = '''
        使用SQL注入修改数据: 课程内容
        ++++++++++++++++++++++++##################### 
        下面的表单允许用户查看与用户id相关联的薪资（来自名为salaries的表）。
        此表单易受字符串SQL注入攻击。为了通过本课程，使用SQL注入修改userid jsmith的薪资。

        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Add_Data_with_SQL_Injection(self,event):
        explain = '''
        使用SQL注入添加数据: 课程内容
        ++++++++++++++++++++++++##################### 
        下面的表单允许用户查看与用户id相关联的薪资（来自名为salaries的表）。
        此表单易受字符串SQL注入攻击。为了通过本课程，请使用SQL注入将记录添加到表中。

        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Database_Backdoors(self,event):
        explain = '''
        使用SQL添加后门: 课程内容
        ++++++++++++++++++++++++##################### 
        第1步，使用字符串SQL注入执行多个SQL语句。 本课的第一步是教您如何使用易受攻击的字段创建两个SQL语句。 
        第一个是系统的，第二个完全是您的。 您的帐户ID为101。此页面可让您查看密码，ssn和薪水。 尝试注入另一个以将薪水更新为更高的水平
        第2步：使用字符串SQL注入注入后门。
        本课程的第二个阶段是教您如何使用易受攻击的字段来注入数据库工作或后门。现在尝试使用相同的技术注入一个触发器，它将充当SQL后门，触发器的语法是：
        注意，实际上不会执行任何操作，因为当前的底层数据库不支持触发器。
        '''
        self.owasp_unified_exploit(explain)
    
    def owasp_set_Improper_Error_Handling(self,event):
        explain = '''
        Fail Open Authentication Scheme : 课程内容
        ++++++++++++++++++++++++#####################
        失败开放式身份验证方案
        由于身份验证机制中的错误处理问题，可以在不输入密码的情况下以“webgoat”用户身份进行身份验证。尝试以webgoat用户身份登录而不指定密码。
        登录
        请登录您的帐户。如果您没有帐户，可以使用OWASP管理员。
        '''
        self.owasp_unified_exploit(explain)
    def owasp_set_Blind_Numeric_SQL_Injection(self,event):
        explain = '''
        Blind_Numeric_SQL_Injection : 课程内容
        ++++++++++++++++++++++++#################
        数字型sql盲注
        下面的表单允许用户输入帐号并确定它是否有效。使用此表单进行盲注测试即另程序返回true或false，检查数据库中的其他条目。
        目标是在表pins中找到cc_number为1111222233334444的行的字段pin的值。字段的类型是int，即整数。
        将定位的pin值放入表单中以通过课程。
        '''
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入课程地址(例如:Screen=7&menu=200)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("&"):
                        params = message.strip()
                        self.control.AppendText("\n")
                        self.control.SetDefaultStyle(wx.TextAttr(wx.GREEN))
                        result = owasp.my_exploit_Blind_Numeric_SQL_Injection(params)
                        if result:
                            self.control.AppendText("           结果: " + result + "\n")
                        else:
                            self.control.AppendText("错误信息: 请求访问出错，请清空数据库，重新收集数据!")
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()

    def owasp_set_Blind_Numeric_SQL_Injection(self,event):
        explain = '''
        Blind_Numeric_SQL_Injection : 课程内容
        ++++++++++++++++++++++++#################
        数字型sql盲注
        下面的表单允许用户输入帐号并确定它是否有效。使用此表单进行盲注测试即另程序返回true或false，检查数据库中的其他条目。
        目标是在表pins中找到cc_number为1111222233334444的行的字段pin的值。字段的类型是int，即整数。
        将定位的pin值放入表单中以通过课程。
        '''
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入课程地址(例如:Screen=7&menu=200)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("&"):
                        params = message.strip()
                        self.control.AppendText("\n")
                        self.control.SetDefaultStyle(wx.TextAttr(wx.GREEN))
                        result = owasp.my_exploit_Blind_Numeric_SQL_Injection(params)
                        if result:
                            self.control.AppendText("           结果: " + result + "\n")
                        else:
                            self.control.AppendText("错误信息: 请求访问出错，请清空数据库，重新收集数据!")
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def owasp_set_Blind_String_SQL_Injection(self,event):
        explain = '''
        Blind_String_SQL_Injection : 课程内容
        ++++++++++++++++++++++++#################
        字符型sql盲注
        下面的表单允许用户输入帐号并确定它是否有效。使用此表单进行盲注测试即另程序返回true或false，检查数据库中的其他条目。
        参考Ascii值：'A'=65 'Z'=90 'a'=97 'z'=122
        目标是在表pins中为 cc_number 为4321432143214321的行查找字段名的值。字段的类型是varchar，它是一个字符串。
        把发现的名字填在表格里，通过这堂课。只有发现的名字才应该放在表单域中，注意拼写和大小写
        '''
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入课程地址(例如:Screen=7&menu=200)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("&"):
                        params = message.strip()
                        self.control.AppendText("\n")
                        self.control.SetDefaultStyle(wx.TextAttr(wx.GREEN))
                        result = owasp.my_exploit_Blind_String_SQL_Injection(params)
                        if result:
                            self.control.AppendText("           结果: " + result + "\n")
                        else:
                            self.control.AppendText("错误信息: 请求访问出错，请清空数据库，重新收集数据!")
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def owasp_set_Insecure_Communication(self,event):
        explain = '''
        Insecure Communication : 课程内容
        ++++++++++++++++++++++++#####################
        不安全通信
        阶段1：在这个阶段你必须嗅出密码。并在登录后回答问题。
        解决方案: 使用wireshark嗅探http流量,得到用户名和密码即可
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Insecure_Configuration(self,event):
        explain = '''
        Insecure Configuration : 课程内容
        ++++++++++++++++++++++++#####################
        不安全配置
        *您的目标应该是尝试猜测“config”接口的URL。
        *“config” URL仅对维护人员可用。
        *应用程序未检查水平权限。
        通过强制浏览猜测配置管理页面.
        解决方案:
        浏览器的地址栏中分别输入:
        http://localhost:8080/WebGoat/config
        http://localhost:8080/WebGoat/conf
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Insecure_Storage(self,event):
        explain = '''
        Insecure Storage : 课程内容
        ++++++++++++++++++++++++#####################
        不安全存储
        本课程将使用户熟悉不同的编码方案。
        解决方案:
        先在 Enter a string: 输入 abc, 点击Go
        再在 Enter a string: 输入 acc, 点击Go
        则解决此问题
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Malicious_Execution(self,event):
        explain = '''
        Malicious File Execution : 课程内容
        ++++++++++++++++++++++++#####################
        恶意文件执行
        下面的表单允许您上载将显示在此页上的图像。这样的功能经常出现在基于web的讨论板和社交网站上。此功能易受恶意文件执行的攻击。
        为了通过这一课，上传并运行一个恶意文件。为了证明您的文件可以执行，它应该创建另一个名为：(这是我这边的地址，我部署的是开发版本)
        D:\javawork\.metadata\.plugins\org.eclipse.wst.server.core\tmp1\wtpwebapps\WebGoat\mfe_target\guest.txt
        大家在./utils/execfile/malicious.jsp修改恶意文件的地址
        '''
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入课程地址(例如:Screen=49&menu=1600)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("&"):
                        params = message.strip()
                        self.control.AppendText("\n")
                        self.control.SetDefaultStyle(wx.TextAttr(wx.GREEN))
                        result = owasp.my_exploit_malicious_execution(params)
                        if result:
                            self.control.AppendText("           结果:\n")
                            self.control.AppendText(result)
                        else:
                            self.control.AppendText("错误信息: 请求访问出错，请清空数据库，重新收集数据!")
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    
    def owasp_set_Bypass_HTML_Field_Restrictions(self,explain):
        explain = '''
        Bypass_HTML_Field_Restrictions : 课程内容
        ++++++++++++++++++++++++#####################
        绕过html字段限制
        下面的表单使用HTML表单字段限制。为了通过本课程，请提交包含不允许值的每个字段的表单。必须在一次表单提交中提交所有六个字段的无效值。
        '''
        self.owasp_unified_exploit(explain)

    def owasp_set_Exploit_Hidden_Fields(self,explain):
        explain = '''
        Exploit_Hidden_Fields : 课程内容
        ++++++++++++++++++++++++#####################
        利用隐藏字段
        如果您还没有购买HDTV，请尝试以低于购买价格的价格购买HDTV。
        '''
        self.owasp_unified_exploit(explain)

    def owasp_set_Exploit_Unchecked_Email(self,explain):
        explain = '''
        Exploit_Unchecked_Email : 课程内容
        ++++++++++++++++++++++++#####################
        利用未校验的电子邮件
        此表单是客户支持页的示例。使用以下表单尝试：
        1） 向网站管理员发送恶意脚本。
        2） 从OWASP向“朋友”发送恶意脚本。
        '''
        self.owasp_unified_exploit(explain)

    def owasp_set_Bypass_Client_Side_JavaScript_Validation(self,explain):
        explain = '''
        Bypass_Client_Side_JavaScript_Validation : 课程内容
        ++++++++++++++++++++++++#####################
        绕过客户端JavaScript验证 
        此网站执行客户端和服务器端验证。在
        这个练习中，您的工作是中断客户端验证并发送它不期望的输入。你必须同时破解所有7个验证器。
        '''
        self.owasp_unified_exploit(explain)
    
    def owasp_set_Spoof_an_Authentication_Cookie(self,explain):
        explain = '''
        Spoof an Authentication Cookie : 课程内容
        ++++++++++++++++++++++++#####################
        用户应该能够绕过身份验证检查。
        使用webgoat/webgoat帐户登录以查看发生了什么。
        您也可以尝试aspect/aspect。
        当您了解身份验证cookie时，请尝试将您的身份更改为alice。

        '''
        self.owasp_unified_exploit(explain)
            
    def owasp_set_Hijack_a_Session(self,event):
        explain = '''
        Hijack_a_Session : 课程内容
        ++++++++++++++++++++++++#####################
        劫持会话
        开发自己会话id的应用程序开发人员常常忘记将安全性所必需的复杂性和随机性结合起来。
        如果用户特定的会话ID不复杂且不随机，则应用程序极易受到基于会话的暴力攻击。
        此课程是暴力破解脆弱性的会话ID，即遵循一定规则生成会话ID的程序。
        解决方案：
        在头信息的cookie字段，增加AuthCookie=65432fdjmb，则完成此课程。
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Hijack_a_Session(self,event):
        explain = '''
        Hijack_a_Session : 课程内容
        ++++++++++++++++++++++++#####################
        劫持会话
        会话 也可以称为 session
        开发自己会话id的应用程序开发人员常常忘记将安全性所必需的复杂性和随机性结合起来。
        如果用户特定的会话ID不复杂且不随机，则应用程序极易受到基于会话的暴力攻击。
        此课程是暴力破解脆弱性的会话ID，即遵循一定规则生成会话ID的程序。
        （注意：会话劫持在现在的互联网程序中，可以成功的概率极低。会话劫持就是会话破解，会话预测）
        攻击会话的三种方式:
        1、预测 就是本课程提供的练习
        2、嗅探 
        3、窃取 这个一般是通过xss漏洞或者csrf钓鱼的方式获得
        4、固定 
        解决方案：
        在头信息的cookie字段，增加AuthCookie=65432fdjmb，则完成此课程。
        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Session_Fixation(self,event):
        explain = '''
        Session_Fixation : 课程内容
        ++++++++++++++++++++++++#####################
        会话固定
        你是黑客Joe ，你想偷jane的会话。给受害者发一封准备好的邮件，看起来像是银行的官方邮件。
        下面准备了一个模板消息，您需要在电子邮件内的链接中添加会话ID（SID）。更改链接以包含SID。
        什么是会话固定？
        会话固定是从黑客，也就是攻击者的角度描述的，把两个词反过来，称为固定会话更好理解，就是攻击者通过社会工程的方式，就是诱骗的方式，
        让受害者点击恶意链接，链接请求中包含攻击者指定的会话ID也就是从目标网站获取的sessionID，目的是让攻击者设置的会话ID变成有效的会话ID，也就是受害者的会话ID，
        当然了，前提是受害者正在访问目标网站，这样就可以访问目标网站的受害者的账户信息。

        解决方案：
        阶段1：您必须向Jane发送一封准备好的邮件，该邮件看起来像是来自Goat Hills Financial的邮件，其中包含会话ID的链接。邮件已经准备好了。
        我们修改邮件内容 ：<a href=http://localhostattack?Screen=46&menu=320&SID=session4jane> (你们的Screen=46&menu=320这个地址可能和我的不一样)
        点击 send mail 按钮就可以完成此阶段
        '''
        self.owasp_unified_explain(explain)
    def owasp_Create_a_SOAP_Request(self,event):
        explain = '''
        Create_a_SOAP_Request : 课程内容
        ++++++++++++++++++++++++#####################
        建立一个soap请求
        Web服务通过SOAP请求进行通信。
        这些请求被提交到web服务，试图执行在web服务定义语言（WSDL）中定义的函数。
        让我们了解一下WSDL文件。查看WebGoat的web服务描述语言（WSDL）文件。

        SOAP 是基于 XML 的简易协议，可使应用程序在 HTTP 之上进行信息交换。 
            SOAP 指简易对象访问协议
            SOAP 是一种通信协议
            SOAP 用于应用程序之间的通信
            SOAP 是一种用于发送消息的格式
            SOAP 被设计用来通过因特网进行通信
            SOAP 独立于平台
            SOAP 独立于语言
            SOAP 基于 XML
            SOAP 很简单并可扩展
            SOAP 允许您绕过防火墙
            SOAP 将被作为 W3C 标准来发展
        soap的基本结构
            <?xml version="1.0"?>
            <soap:Envelope
            xmlns:soap="http://www.w3.org/2001/12/soap-envelope"
            soap:encodingStyle="http://www.w3.org/2001/12/soap-encoding">

            <soap:Header>
            ...
            </soap:Header>

            <soap:Body>
            ...
            <soap:Fault>
            ...
            </soap:Fault>
            </soap:Body>

            </soap:Envelope> 
        阶段1： WSDL中定义了多少个操作？ 4个 getFirstName、getLastName、getCreditCard、getLoginCount，填4就行了
        阶段2：现在，“getFirstNameRequest”方法中的（id）参数的类型是什么：int

        '''
        self.owasp_unified_explain(explain)
    def owasp_WSDL_Scanning(self,event):
        explain = '''
        WSDL Scanning : 课程内容
        ++++++++++++++++++++++++#####################
        总体目标：
        这个屏幕是web服务的API。检查此web服务的WSDL文件并尝试获取一些客户信用号。
        WSDL（网络服务描述语言，Web Services Description Language）是一门基于 XML 的语言，用于描述 Web Services 以及如何对它们进行访问。
            WSDL 指网络服务描述语言
            WSDL 使用 XML 编写
            WSDL 是一种 XML 文档
            WSDL 用于描述网络服务
            WSDL 也可用于定位网络服务
            WSDL 还不是 W3C 标准

            元素 	        定义
        <portType> 	web service 执行的操作
        <message> 	web service 使用的消息
        <types> 	web service 使用的数据类型
        <binding> 	web service 使用的通信协议

        基本结构
        <definitions>

        <types>
        definition of types........
        </types>

        <message>
        definition of a message....
        </message>

        <portType>
        definition of a port.......
        </portType>

        <binding>
        definition of a binding....
        </binding>

        </definitions>               
        '''
        self.owasp_unified_explain(explain)

    def owasp_set_Web_Service_SQL_Injection(self,event):
        explain = '''
        Web Service SQL Injection : 课程内容
        ++++++++++++++++++++++++#####################
        Web服务通过使用SOAP请求进行通信。这些请求被提交到web服务，试图执行在web服务定义语言（WSDL）文件中定义的函数。
        检查web服务描述语言（WSDL）文件并尝试获取多个客户信用卡号码。
        您将看不到返回到此屏幕的结果。当你相信你成功了，刷新页面，寻找“green star”。

        '''
        self.owasp_unified_explain(explain)
    def owasp_set_Web_Service_SAX_Injection(self,event):
        explain = '''
        Web_Service_SAX_Injection : 课程内容
        ++++++++++++++++++++++++#####################
        Web Service SAX注入
        SAX（simple API for XML）是一种XML解析的替代方法。
        相比于DOM，SAX是一种速度更快，更有效的方法。
        它逐行扫描文档，一边扫描一边解析。而且相比于DOM，SAX可以在解析文档的任意时刻停止解析，但任何事物都有其相反的一面，对于SAX来说就是操作复杂。
        一些web接口在后台使用web服务。如果前端依赖web服务进行所有输入验证，则可能会损坏web接口发送的XML。
        在本练习中，尝试更改101以外的用户的密码。
        '''
        self.owasp_unified_explain(explain)
    def owasp_unified_exploit(self,explain):
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入地址,exploit函数名,类型req或者resp,用#号连接(例如:Screen=55&menu=100#my_exploit_http_split#req)",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    if message.find("#"):
                        sign,exploit,otype= message.strip().split("#") 
                        conf.set_owasp_sign(sign)
                        conf.set_owasp_exploit(exploit)
                        conf.set_owasp_type(otype)
                    else:
                        dlg_tip.ShowModal()
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()

    def owasp_unified_explain(self,explain):
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            self.control.AppendText(explain)
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def samllTools_base64_coder(self,event):
        if self.start.IsEnabled():
            dlg = wx.TextEntryDialog(None,u"请输入",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    message = message.strip()
                    str_coder = st.base64_coder(message)
                    self.control.AppendText("           base64编码结果: "+str_coder)
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def samllTools_base64_encoder(self,event):
        if self.start.IsEnabled():
            dlg = wx.TextEntryDialog(None,u"请输入",u"设置",u"")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    message = message.strip()
                    str_encoder = st.base64_encoder(message)
                    self.control.AppendText("           base64解码结果: "+str_encoder)
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def samllTools_wireshark_open(self,event):
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            conf = config() 
            tshark_path = conf.get_wireshark_path()
            wireshark = ms(tshark_path)
            self.control.AppendText("               开启wireshak嗅探,现在开始按照课程要求操作!\n")
            cmdStr = wireshark.startUpTshark()
            self.control.AppendText("               等待完成!持续时间100秒\n")
            thread.start_new_thread(st.runCmd,(cmdStr,))          
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def samllTools_wireshark_analysis(self,event):
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            conf = config() 
            tshark_path = conf.get_wireshark_path()
            filter_pcap = conf.get_filter_pcap()
            wireshark = ms(tshark_path,display_filter=filter_pcap)
            self.control.AppendText("               数据包分析结果:\n")
            anaStr = wireshark.analysisData()
            for a in anaStr:
                 self.control.AppendText("               " + str(a) + "\n")     
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def smallTools_hydra_help(self,event):
        explain = '''
        hydra : 是一个 猜测/破解 有效登录/密码 的工具，支持多种协议的破解,再次对此工具的使用进行封装,用来测试存在暴力破解的漏洞.
        ###########################################
        参数说明:
        hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e ns]
        [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-f] [-s PORT] [-S] [-vV] server service [OPT]
        -h : hydra的使用说明
        -R ：继续从上一次进度接着破解
        -S ：执行SSL链接
        -I : 忽略已破解的文件(不超过10秒的等待时间)
        -s PORT : 指定端口
        -l LOGIN 或者 -L FILE: 指定用户名破解，或者，指定用户名字典
        -p PASS 或者 -P FILE : 指定密码破解， 或者，指定密码字典
        -x MIN:MAX:CHARSET : 强制生成密码字典，可以使用 "hydra -x -h "查看使用说明
           举例: -x 3:5:a : 生成长度为3到5个的密码，最后一个a表示密码全是小写字母
                 -x 5:8:A : 生成长度为5到8个的密码，最后一个A表示密码全是大写字母
                 -x 1:8:1 : 生成长度为1到8个的密码，最后一个1表示密码全是数字
                 -x 1:8:A1 : 生成长度为1到8个的密码，大写字母和数字混合
                 -x 1:8:/$ : 生成长度为1到8个的密码，/ 和 $ 组合
                 -x 1:8:aA1 : 生成长度为1到8个的密码，大小写字母和数字混合
                 -x 1:8:aA1 -y : 生成长度为1到8个的密码，仅包含a，A 和 1，禁用a A 1的特殊意义
           -y : 禁用符号的特殊意义使用
        -e nsr : n：空密码试探，s：使用指定用户和密码试探, r: 反向链接登录
        -u ：循环用户，与-x 命令使用
        -C FILE : 使用冒号分割格式，例如: "用户名:密码",而不是 -L 和 -P 的模式
        -M FILE : 要破解的服务地址列表，文件中一行一个，通过 : 指定端口
        -o FILE : 指定结果的输出文件
        -f 或者 -F : 在使用-M参数一行，找到第一对登录名或密码后终止运行
        -t TASKS : 指定同时运行的线程数，默认是16个
        -T TASKS : 由于-M 参数，默认线程数是64个
        -w TIME : 设置超时响应时间，默认是30s
        -W TIME : 设置每个线程的连接数
        -c TIME : 设置所有线程每次登录的等待时间
        -4 或者 -6 :设置IP地址类型,4: IPv4(默认) 6：IPV6
        -v 或者 -V 或者 -d ： 详细模式  或者 显示每个用户名和密码的登录过程 或者 debug模式
        -O : 使用旧的SSL协议 sslv2 sslv3
        -K : 不要重做失败的尝试，用于-M的批量扫描
        -q : 不显示连接错误的信息
        -U : 服务模块详细使用信息
        -m OPT : 使用特殊模块选项，可以用-U查看特殊服务模块
        server : 目标IP
        service ： 要破解的服务
        hydra 支持的服务类型:
        adam6500,asterisk,cisco,cisco-enable,
        cvs,ftp[s],http[s]-{head|get|post},http[s]-{get|post}-form,
        http-proxy,http-proxy-urlenum,icq,imap[s],irc,ldap2[s],
        ldap3[-{cram|digest}md5][s],mssql,mysql,nntp,
        oracle-listener,oracle-sid,pcanywhere,pcnfs,
        pop3[s],postgres,radmin2,rdp,redis,rexec,
        rlogin,rpcap,rsh,rtsp,s7-300,sip,smb,smtp[s],
        smtp-enum,snmp,socks5,ssh,sshkey,
        teamspeak,telnet[s],vmauthd,vnc,xmpp
        '''
        self.owasp_unified_explain(explain)
    def smallTools_hydra_path(self,event):
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入hydra工具路径,默认路径:D:\\hydra\\",u"设置",value="D:\\hydra\\")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    conf.set_hydra_path(message)
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()        
    def smallTools_hydra_example(self,event):
        dictPath = os.path.abspath(os.curdir) + "\\dict\\"
        userDict = dictPath + "userdict.txt"
        passDict = dictPath + "passdict.txt"
        pathDes = "\n"+"\n"+"   当前项目已存在的用户名字典路径: " + userDict + "\n" + "   当前项目已存在密码字典路径: " + passDict + "\n"
        explain = pathDes + '''

        hydra -L E:\\project\\py\\mitm_modify\\dict\\testuser.txt -P E:\\project\py\\mitm_modify\\dict\\testpass.txt -t 1 -s 8080 -f localhost http-post-form "/WebGoat/attack?Screen=61&menu=500:user=^USER^&pass=^PASS^&Submit=Submit:success"
        1、破解ssh： 
        hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns ip ssh 
        hydra -l 用户名 -p 密码字典 -t 线程 -o save.log -vV ip ssh 
                
        2、破解ftp： 
        hydra ip ftp -l 用户名 -P 密码字典 -t 线程(默认16) -vV 
        hydra ip ftp -l 用户名 -P 密码字典 -e ns -vV 
                
        3、get方式提交，破解web登录： 
        hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns ip http-get /admin/ 
        hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns -f ip http-get /admin/index.php
                
        4、post方式提交，破解web登录： 
        hydra -l 用户名 -P 密码字典 -s 80 ip http-post-form "/admin/login.php:username=^USER^&password=^PASS^&submit=login:sorry password" 
        hydra -t 3 -l admin -P pass.txt -o out.txt -f 10.36.16.18 http-post-form "login.php:id=^USER^&passwd=^PASS^:<title>wrong username or password</title>" 
        （参数说明：-t同时线程数3，-l用户名是admin，字典pass.txt，保存为out.txt，-f 当破解了一个密码就停止， 10.36.16.18目标ip，http-post-form表示破解是采用http的post方式提交的表单密码破解,<title>中 的内容是表示错误猜解的返回信息提示。） 
                
        5、破解https： 
        hydra -m /index.php -l muts -P pass.txt 10.36.16.18 https 
                       
        6、破解teamspeak： 
        hydra -l 用户名 -P 密码字典 -s 端口号 -vV ip teamspeak 
                        
        7、破解cisco： 
        hydra -P pass.txt 10.36.16.18 cisco 
        hydra -m cloud -P pass.txt 10.36.16.18 cisco-enable 
                        
        8、破解smb： 
        hydra -l administrator -P pass.txt 10.36.16.18 smb 
                        
        9、破解pop3： 
        hydra -l muts -P pass.txt my.pop3.mail pop3 
                        
        10、破解rdp： 
        hydra ip rdp -l administrator -P pass.txt -V 
                       
        11、破解http-proxy： 
        hydra -l admin -P pass.txt http-proxy://10.36.16.18 
                        
        12、破解imap： 
        hydra -L user.txt -p secret 10.36.16.18 imap PLAIN 
        hydra -C defaults.txt -6 imap://[fe80::2c:31ff:fe12:ac11]:143/PLAIN
        '''
        self.owasp_unified_explain(explain)
    def smallTools_hydra_exec(self,event):
        if self.start.IsEnabled():
            conf = config()
            dlg = wx.TextEntryDialog(None,u"请输入命令行，参考命令示例",u"设置",value="hydra -h")
            dlg_tip = wx.MessageDialog(None, "输入错误!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    thread.start_new_thread(st.cmdExec,(message,self.control))
                else:
                    dlg_tip.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()                
    def db_get_table_info(self,event):
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            tabName = mitmSql.get_sqlite_tables()
            self.control.AppendText("数据库表信息:\n")
            for t in tabName:
                if t == "sqlite_sequence":
                    continue
                self.control.AppendText(t)
                self.control.AppendText("\n")
            self.control.AppendText("mitmhttp:监控信息表,包含请求和响应信息\n")
            self.control.AppendText("mitm_rep_info:请求信息表\n")
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def db_get_fileds_info(self,event):
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            tabName = mitmSql.get_sqlite_tables()
            self.control.AppendText("字段信息:\n")
            for t in tabName:
                if t == "sqlite_sequence":
                    continue
                self.control.AppendText(t)
                self.control.AppendText("\n")
                fileds = mitmSql.mitm_show_table_field(t)
                for f in fileds:
                    text = "---- " + f[1] + ", 类型: " + f[2] + "\n"
                    self.control.AppendText(text)
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal() 
    def db_get_table_data(self,event):
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            dlg = wx.TextEntryDialog(None,u"请输入要查询的表名称:",u"数据查询",u"mitmhttp")
            keys = []
            text = ""
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    tData = mitmSql.mitm_select_all(message)
                    fields = mitmSql.mitm_show_table_field(message)
                    self.control.AppendText(message+" 表数据如下：\n")
                    for f in fields:
                        text += f[1] + "     |     "
                        keys.append(f[1])
                    text += "\n"
                    self.control.AppendText(text)
                    text = ""
                    for t in tData:
                        for k in keys:
                            text += str(t[k]) + "     |     "
                        text += "\n"
                        self.control.AppendText(text)
                        text = ""
                else:
                    messageBox = wx.MessageDialog(None, "不能为空!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
                    messageBox.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()                               
    def db_reset_table(self,event):
        if self.start.IsEnabled():
            self.control.Clear()
            self.control.SetDefaultStyle(wx.TextAttr(wx.RED))
            dlg = wx.TextEntryDialog(None,u"请输入要清空的表名称:",u"数据重置",u"mitmhttp")
            if dlg.ShowModal() == wx.ID_OK:
                message = dlg.GetValue()
                if message:
                    mitmSql.mitm_del_data_all(message)
                    mitmSql.mitm_reset_autoid(message)
                    self.control.AppendText(message + "数据已清空!")
                else:
                    messageBox = wx.MessageDialog(None, "不能为空!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
                    messageBox.ShowModal()
        else:
            messageBox = wx.MessageDialog(None, "请先停止监控!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
            messageBox.ShowModal()
    def onClose(self,event):
        pass
    def manualDes(self):
        self.Destroy()                                            
if __name__ == "__main__":
    try:
        app = wx.PySimpleApp()
        frame=MainWindow(None,-1, '安全测试工具V1.2')
        app.MainLoop()
    except Exception as e:
        app.ExitMainLoop()
        
