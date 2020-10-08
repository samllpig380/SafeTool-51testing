#!/usr/bin/env python
# -*- coding:utf-8 -*-
import re
class Regex:
    __regex={
        'email':'^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$',
        'domainName':'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(/.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+/.?',#域名
        'internetURL':'[a-zA-z]+://[^\s]*',#httpUrl,^http://([\w-]+\.)+[\w-]+(/[\w-./?%&=]*)?$
        'mobile':'^([1][3,4,5,6,7,8,9])\d{9}$',#^(13[0-9]|14[0-9]|15[0-9]|16[0-9]|17[0-9]|18[0-9]|19[0-9])\d{8}$
        'telephone':'^(\(\d{3,4}-)|\d{3.4}-)?\d{7,8}$',
        'cityTelephone':'\d{3}-\d{8}|\d{4}-\d{7}',
        'idCard':'^((\d{18})|([0-9x]{18})|([0-9X]{18}))$',
        'date':'^\d{4}-\d{1,2}-\d{1,2}',
        'chinese':'[\u4e00-\u9fa5]',
        'qqNumber':'[1-9][0-9]{4,}',
        'postalCode':'[1-9]\d{5}(?!\d)',
        'ipAddr':'\d+\.\d+\.\d+\.\d+',
        'htmlScript':'<script(.*?)</script>',
        'htmlStyle':'<style(.*?)</style>'
    }
    def get_email(self):
        return self.__regex['email']
    def get_domainName(self):
        return self.__regex['domainName']
    def get_internetURL(self):
        return self.__regex['internetURL']
    def get_mobile(self):
        return self.__regex['mobile']
    def get_telephone(self):
        return self.__regex['telephone']
    def get_cityTelephone(self):
        return self.__regex['cityTelephone']
    def get_idCard(self):
        return self.__regex['idCard']
    def get_date(self):
        return self.__regex['date']
    def get_chinese(self):
        return self.__regex['chinese']
    def get_qqNumber(self):
        return self.__regex['qqNumber']
    def get_postalCode(self):
        return self.__regex['postalCode']
    def get_ipAddr(self):
        return self.__regex['ipAddr']
    def get_htmlScript(self):
        return self.__regex['htmlScript']
    def get_htmlStyle(self):
        return self.__regex['htmlStyle']
if __name__=="__main__":
    regex = Regex()
    strTest = "ddd中文点点滴滴ddd"
    result = re.findall(regex.get_chinese(),string=strTest,flags=re.S)
    print(result)