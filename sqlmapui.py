#!/usr/bin/env python
# -*- coding:utf-8 -*-
import wx
from wx import stc
class SqlMapWindow(wx.Frame):
    def __init__(self,content):
        self.width=800
        self.height=500
        wx.Frame.__init__(self,None,-1,u'SQLMAP',size=(self.width,self.height),style=wx.DEFAULT_FRAME_STYLE ^ wx.RESIZE_BORDER)
        tb=wx.Frame.CreateToolBar(self,style=wx.TB_FLAT|wx.TB_HORIZONTAL)
        tb.AddTool(104,u"搜索",wx.Bitmap("./ico/python.ico"))
        tb.Realize() 
        self.panel=wx.Panel(self,-1) 
        self.text = stc.StyledTextCtrl(self.panel,-1,pos=(2,2),size=(self.width-10,self.height-50),style=wx.HSCROLL|wx.TE_MULTILINE)
        #self.text=wx.TextCtrl(self.panel,-1,pos=(2,2),size=(self.width-10,self.height-50), style=wx.HSCROLL|wx.TE_MULTILINE)
        self.text.SetBackgroundColour('black')
        self.text.SetForegroundColour(wx.GREEN)
        self.text.AppendText(content)
        self.Bind(wx.EVT_MENU,self.OnToolSelected,id=104)
        self.Bind(wx.EVT_FIND,self.OnFind)
        self.Bind(wx.EVT_FIND_NEXT,self.OnFindNext)
        self.Bind(wx.EVT_FIND_REPLACE,self.OnReplace)
        self.Bind(wx.EVT_FIND_REPLACE_ALL,self.OnReplaceAll)
        self.Bind(wx.EVT_FIND_CLOSE,self.OnFindClose)
        self.search_forward = True
        self.Show()
    def OnToolSelected(self,e):
        if e.GetId()==104:
            self.Search(self.text.GetSelectedText())  
    def Search(self,toSearch):
        data=wx.FindReplaceData()
        data.SetFindString(toSearch)
        dlg=wx.FindReplaceDialog(self,data,u"查找替换", wx.FR_REPLACEDIALOG)
        dlg.Show()
    def OnFind(self,event):
        tosearch=event.GetFindString()
        length=self.text.GetTextLength()
        n=self.text.FindText(0,length,tosearch,event.GetFlags())
        self.CenterPosInView(n)
        sel_len = len(tosearch.encode("utf-8"))
        self.text.SetSelection(n,n+sel_len)
    def OnFindNext(self,event):
        try:
            tosearch = event.GetFindString()
            anchor = self.text.GetAnchor()
            length = self.text.GetTextLength()
            if self.search_forward:
                n=self.text.FindText(anchor+1,length,tosearch,event.GetFlags())
            else:
                n=self.text.FindText(anchor,0,tosearch,event.GetFlags())
            if n != -1:
                self.CenterPosInView(n)
                sel_len=len(tosearch.encode("utf-8"))
                self.text.SetSelection(n[0],n[0]+sel_len)
            else:
                if self.search_forward:
                    message=u"已经到达文件结束处，是否重新搜索？"
                else:
                    message=u"已经到达文件开始处，是否重新搜索？"
                result=dlg=wx.MessageBox(message,"提示信息",wx.YES_NO | wx.CANCEL | wx.ICON_EXCLAMATION,self)
                if result==wx.YES:
                    self.search_forward=not self.search_forward
        except Exception as ex:
            print(ex)            
    def OnFindClose(self,event):
        dlg=event.GetDialog()
        dlg.Destroy()
    def CenterLineInView(self,line):
        nlines=self.text.LinesOnScreen()
        first=self.text.GetFirstVisibleLine()
        target=first+nlines/2
        self.text.LineScroll(0,line-target)
    def CenterPosInView(self,pos):
        line=self.text.LineFromPosition(pos)
        self.CenterLineInView(line)
        self.text.GotoLine(line)
        self.text.GotoPos(pos) 

    def OnReplace(self,event):
        searchStr=event.GetFindString()
        replaceStr=event.GetReplaceString()
        startSel,endSel=self.text.GetSelection()
        if startSel != endSel:
            m=self.text.Replace(startSel,endSel,replaceStr)
            self.OnFindNext(event)
        else:
            self.OnFind(event)
    def OnReplaceAll(self,event):
        pass    
           
def openSqlmapWindow(content):
    try:
        app = wx.App()
        SqlMapWindow(content) 
        app.MainLoop()
    except Exception as e:
        print(e)
        app.ExitMainLoop()
#openSqlmapWindow("test")