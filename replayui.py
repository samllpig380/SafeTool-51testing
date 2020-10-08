#!/usr/bin/env python
# -*- coding:utf-8 -*-
import wx
import sys
import requests
from utils.redisQueue import RedisQueue
import json
repayRq = RedisQueue("repayrq")
class ReplayWindow(wx.Frame):
    def __init__(self,parent, id, title):
        wx.Frame.__init__(self, parent, id, title, pos=(10,10),size=(730,600),style=wx.DEFAULT_FRAME_STYLE ^ wx.RESIZE_BORDER)
        self.reqPanel = wx.Panel(self,style=wx.BORDER_DOUBLE,size=wx.Size(350,200))
        repsPanel = wx.Panel(self,style=wx.BORDER_DOUBLE,size=wx.Size(350,200))
        hBox = wx.BoxSizer(wx.HORIZONTAL)
        reqHBox_1 = wx.BoxSizer(wx.HORIZONTAL)
        reqHBox_2 = wx.BoxSizer(wx.HORIZONTAL)
        reqHBox_3 = wx.BoxSizer(wx.HORIZONTAL)
        reqVBox = wx.BoxSizer(wx.VERTICAL)
        hBox.Add(self.reqPanel,0, wx.ALL| wx.EXPAND, 5)
        hBox.Add(repsPanel,0, wx.ALL| wx.EXPAND, 5)

        reqName = wx.StaticText(self.reqPanel,-1,"发送请求")
        reqName.SetForegroundColour('red')
        

        reqOrderLabel_1 = wx.StaticText(self.reqPanel,-1,"并发模式: ")
        reqOrderList = ["进程","线程"]
        self.reqComBox = wx.ComboBox(self.reqPanel,-1, value =  reqOrderList[1], choices = reqOrderList, style = wx.CB_DROPDOWN)
        reqOrderLabel_2 = wx.StaticText(self.reqPanel,-1,"开启数量: ")
        self.reqNum = wx.TextCtrl(self.reqPanel, value='1',size = (50,25))
        self.reqButton = wx.Button(self.reqPanel,-1,"发送")

        reqHBox_1.Add(reqName,0, wx.ALL| wx.EXPAND , 5)
        reqHBox_2.Add(reqOrderLabel_1,0,wx.ALL| wx.EXPAND , 5)
        reqHBox_2.Add(self.reqComBox,0,wx.ALL| wx.EXPAND , 5)
        reqHBox_2.Add(reqOrderLabel_2,0,wx.ALL| wx.EXPAND , 5)
        reqHBox_2.Add(self.reqNum,0,wx.ALL| wx.EXPAND , 5)
        reqHBox_2.Add(self.reqButton,0,wx.ALL| wx.EXPAND , 5)
        self.reqContents = wx.TextCtrl(self.reqPanel,size = (390,500), style = wx.TE_MULTILINE | wx.HSCROLL)
        reqVBox.Add(reqHBox_1,0,wx.ALL| wx.EXPAND , 5)
        reqVBox.Add(reqHBox_2,0,wx.ALL| wx.EXPAND , 5)
        reqVBox.Add(self.reqContents,0,wx.ALL| wx.EXPAND , 5)
        self.reqPanel.SetSizer(reqVBox)
        
        repsHBox_1 = wx.BoxSizer(wx.HORIZONTAL)
        repsHBox_2 = wx.BoxSizer(wx.HORIZONTAL)
        repsHBox_3 = wx.BoxSizer(wx.HORIZONTAL)
        repsVBox = wx.BoxSizer(wx.VERTICAL)
        repsName = wx.StaticText(repsPanel,-1,"接收响应")
        repsName.SetForegroundColour('red')
        repsOrderLabel_1 = wx.StaticText(repsPanel,-1,"定位文本: ")
        self.repsText = wx.TextCtrl(repsPanel, size = (150,25))
        self.repsSearch = wx.Button(repsPanel,-1,"搜索")
        self.repsContents = wx.TextCtrl(repsPanel,size = (390,500), style = wx.TE_MULTILINE | wx.HSCROLL)
        repsHBox_1.Add(repsName,0, wx.ALL| wx.EXPAND , 5)
        repsHBox_2.Add(repsOrderLabel_1,0, wx.ALL| wx.EXPAND , 5)
        repsHBox_2.Add(self.repsText,0, wx.ALL| wx.EXPAND , 5)
        repsHBox_2.Add(self.repsSearch,0, wx.ALL| wx.EXPAND , 5)
        repsVBox.Add(repsHBox_1,0,wx.ALL| wx.EXPAND , 5)
        repsVBox.Add(repsHBox_2,0,wx.ALL| wx.EXPAND , 5)
        repsVBox.Add(self.repsContents,0,wx.ALL| wx.EXPAND , 5)
        repsPanel.SetSizer(repsVBox)

        self.popMenu = wx.Menu()#创建一个菜单
        popMenuList = [u'方法',u'URL',u'头信息',u'参数',u"字典加载"]
        for text in popMenuList:#填充菜单
            if text == 'separator':
                self.popMenu.AppendSeparator()
                continue
            item = self.popMenu.Append(-1, text) 
            self.Bind(wx.EVT_MENU, self.pop_menu_item_selected, item) 
            self.reqPanel.Bind(wx.EVT_CONTEXT_MENU, self.pop_menu_on_show)#绑定一个显示菜单事件 
                
        self.Bind(wx.EVT_BUTTON,self.sendClick,self.reqButton)
        self.Bind(wx.EVT_BUTTON,self.findStr,self.repsSearch)
        self.SetSizer(hBox)
        self.Show()
        self.initSetReqText()
    def initSetReqText(self):
        result = repayRq.get_wait()
        strValue = str(result[1],'utf-8')
        self.dict_str = json.loads(strValue)
        text = "方法: "+ self.dict_str['method'] + "\n\n"
        text += "URL: "+ self.dict_str['url'] + "\n\n"
        text += "头信息: "+ str(self.dict_str['headers']) + "\n\n"
        text += "参数: "+ str(self.dict_str['params']) + "\n\n"
        text += "主地址: " + self.dict_str['system_name'] + "\n\n"
        self.reqContents.SetValue(text)
    def pop_menu_on_show(self, event):#弹出显示
        pos = event.GetPosition() 
        pos = self.reqPanel.ScreenToClient(pos) 
        self.reqPanel.PopupMenu(self.popMenu, pos)
    def pop_menu_item_selected(self,event):
        text = self.popMenu.GetLabel(event.GetId())
        if text == "方法":
            fixValue = self.inputDig("提交方法修改",self.dict_str['method'])
            self.dict_str['method'] = fixValue
        elif text == "URL":
            fixValue = self.inputDig("URL修改",self.dict_str['url'])
            self.dict_str['url'] = fixValue
        elif text == "头信息":
            fixValue = self.inputDig("头信息修改",str(self.dict_str['headers']))
            self.dict_str['headers'] = json.loads(fixValue)
        elif text == "参数":
            fixValue = self.inputDig("参数修改",self.dict_str['params'])
            self.dict_str['params'] = fixValue
    def send(self,info:dict):
        method = url = headers = params = ''
        text = ''
        if "method" in info.keys():
            if info['method'] == "GET":
                if 'url' in info.keys():
                    url = info['url']
                    if 'headers' in info.keys():
                        headers = info['headers']
                        text = requests.get(url,headers=headers)
            elif info['method'] == "POST":
                if 'url' in info.keys():
                    url = info['url']
                    if 'headers' in info.keys():
                        headers = info['headers']
                        if 'params' in info.keys():
                            params = info['params']
                            text = requests.post(url,headers = headers,data = params)
        return text
    def inputDig(self,title,value):
        dlg = wx.TextEntryDialog(None,u"请输入要修改的值",title,value = value)
        dlg_tip = wx.MessageDialog(None, "参数为空", u"提示信息", wx.OK | wx.ICON_INFORMATION)
        if dlg.ShowModal() == wx.ID_OK:
            message = dlg.GetValue()
            if message:
                return message
            else:
                dlg_tip.ShowModal()
        return ""    
    def sendClick(self,event):
        response = self.send(self.dict_str)
        self.repsContents.AppendText(response.text)
    def findStr(self,event):
        searchStr = self.repsText.GetValue()
        contents = self.repsContents.GetValue()
        if contents.find(searchStr) > -1 :
            messageBox = wx.MessageDialog(None, "搜索的内容存在!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
        else:
            messageBox = wx.MessageDialog(None, "内容不存在!", u"提示信息", wx.OK | wx.ICON_INFORMATION)
        messageBox.ShowModal()                      
def openReplayWindow():
    try:
        app = wx.App()
        ReplayWindow(None,-1,"重放窗口")
        app.MainLoop()
    except Exception as e:
        print(e)
        app.ExitMainLoop()
    
