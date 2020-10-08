#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sqlite3
import os
import traceback
import json
#global var
#数据库文件绝对路径
DB_PATH = os.path.join(os.getcwd(), "db")
DB_FILE_PATH = DB_PATH + "\\mitm.db"
###############################################################
####            mitm表操作     START
###############################################################
def get_conn(path):
    conn = sqlite3.connect(path)
    if os.path.exists(path) and os.path.isfile(path):
        return conn
    else:
        conn = None
        return sqlite3.connect(':memory:')
def get_cursor(conn):
    if conn is not None:
        return conn.cursor()
    else:
        return get_conn('').cursor()
def create_table(conn, sql):
    '''创建数据库表'''
    if sql is not None and sql != '':
        cu = get_cursor(conn)
        cu.execute(sql)
        conn.commit()
        print('创建数据库表成功!')
        close_all(conn, cu)
    else:
        print('the [{}] is empty or equal None!'.format(sql))
def close_all(conn, cu):
    '''关闭数据库游标对象和数据库连接对象'''
    try:
        if cu is not None:
            cu.close()
    finally:
        if conn is not None:
            conn.close()
def mitm_get_cur(path):
    conn = get_conn(path)
    cu = get_cursor(conn)
    return conn,cu
def create_table_mitm():
    print('创建数据库表...')
    create_table_sql = '''CREATE TABLE `mitmhttp` (
                          `id` integer PRIMARY KEY autoincrement,
                          `method` varchar(20) NOT NULL,
                          `url` varchar(200) DEFAULT NULL,
                          `headers` varchar(4) DEFAULT NULL,
                          `params` varchar(1000) DEFAULT NULL,
                          `create_time` varchar(100) DEFAULT NULL,
                          `system_name` varchar(100) DEFAULT NULL,
                          `is_request` integer NOT NULL,
                          `is_response` integer NOT NULL
                        )'''
    conn = get_conn(DB_FILE_PATH)
    create_table(conn, create_table_sql)
def create_table_mitm_rep_info():
    print("创建数据库表...")
    create_table_sql = '''CREATE TABLE `mitm_rep_info` (
                          `id` integer PRIMARY KEY autoincrement,
                          `name` varchar(20) NOT NULL,
                          `headers` json DEFAULT NULL,
                          `create_time` varchar(100) DEFAULT NULL
                        )'''
    conn = get_conn(DB_FILE_PATH)
    create_table(conn, create_table_sql)    
def drop_table_mitm(table):
    if table is not None and table != '':
        sql = 'DROP TABLE IF EXISTS ' + table
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql)
        conn.commit()
        print('drop[{}]sucess!'.format(table))
        close_all(conn, cu)
    else:
        print('table name!')
#增加字段
def mitm_add_field(table,field,fieldType):
    try:
        add_sql = '''ALTER TABLE `'''+table + '''`ADD COLUMN `'''+field+'''`'''+fieldType+''' NOT NULL'''
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(add_sql)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
#查看表结构select * from sqlite_master where name = "table_name"
def mitm_show_table_structure(table):
    try:
        sql = 'select * from sqlite_master where name = ?'
        data = (table,)
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql,data)
        r = cu.fetchall()
        if len(r)>0:
            for e in range(len(r)):
                print(r[e])
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
#获取表字段PRAGMA table_info('tablename')
def mitm_show_table_field(table):
    try:
        sql = '''PRAGMA table_info('''+table+''')'''
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql)
        r = cu.fetchall()
        filedInfo = []
        if len(r)>0:
            for e in range(len(r)):
                filedInfo.append(r[e])
        close_all(conn,cu)
        return filedInfo
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
#插入数据 table:mitmhttp
def mitm_insert_data(dataDict):
    try:
        sql = '''INSERT INTO mitmhttp(method,url,headers,params,create_time,system_name,is_request,is_response) values (?, ?,?, ?, ?,?,?,?)'''
        data = (dataDict['method'],dataDict['url'],dataDict['headers'],
                dataDict['params'],dataDict['create_time'],dataDict['system_name'],
                dataDict['is_request'],dataDict['is_response'])
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql,data)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
#插入数据 table:mitm_rep_info
def mitm_insert_data_rep_info(dataDict):
    try:
        sql = '''INSERT INTO mitm_rep_info(name,headers,create_time) values (?, ?,?)'''
        data = (
            dataDict['name'],dataDict['headers'],dataDict['create_time']
        )
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql,data)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
       print(traceback.print_exc())
       close_all(conn,cu) 
def mitm_del_data_all(table):
    try:
        sql = '''delete from '''+table
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)

def mitm_del_data_filter(table,field,value):
    try:
        sql = '''delete from '''+table+''' where '''+field+''' = ?'''
        data = (value,)
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql,data)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
#查询全部数据
def mitm_select_all(table):
    try:
        data_dict = {}
        result = []
        sql = '''select * from '''+table
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql)
        r = cu.fetchall()
        if table == "mitmhttp":
            if len(r)>0:
                for e in range(len(r)):
                    data_dict['id'] = r[e][0]
                    data_dict['method'] = r[e][1]
                    data_dict['url'] = r[e][2]
                    data_dict['headers'] = eval(r[e][3])
                    data_dict['params'] = r[e][4]
                    data_dict['create_time']  = r[e][5]
                    data_dict['system_name'] = r[e][6]
                    data_dict['is_request'] = r[e][7]
                    data_dict['is_response'] = r[e][8]
                    result.append(data_dict)
                    data_dict = {}
        elif table == "mitm_rep_info":
            if len(r)>0:
                for e in range(len(r)):
                    data_dict['id'] = r[e][0]
                    data_dict['name'] = r[e][1]
                    data_dict['headers'] = eval(r[e][2])
                    data_dict['create_time'] = r[e][3] 
                    result.append(data_dict) 
                    data_dict = {}            
        close_all(conn,cu)
        return result
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)

#按条件查询
def mitm_select_data_filter(table,field,value):
    dataDict = {}
    result = []
    sql = '''select * from '''+table+''' where '''+field+''' = ?'''
    data = (value,)
    conn,cu = mitm_get_cur(DB_FILE_PATH)
    cu.execute(sql,data)
    r = cu.fetchall()
    if table == "mitmhttp":
        if len(r)>0:
            for e in range(len(r)):
                dataDict['method'] = r[e][1]
                dataDict['url'] = r[e][2]
                dataDict['headers'] = eval(r[e][3])
                dataDict['params'] = r[e][4]
                dataDict['create_time']  = r[e][5]
                dataDict['system_name'] = r[e][6]
                dataDict['is_request'] = r[e][7]
                dataDict['is_response'] = r[e][8]
                #print(data_dict)
                result.append(dataDict)
                data_dict = {}
    elif table == "mitm_rep_info":
        if len(r)>0:
            for e in range(len(r)):
                dataDict['name'] = r[e][1]
                dataDict['headers'] = eval(r[e][2])
                dataDict['create_time'] = r[e][3] 
                result.append(dataDict)
                data_dict = {}             
    close_all(conn,cu)
    return result
#最大值
def mitm_select_max_data(table,field,value,maxField):
    sql = '''select max('''+maxField+''') from '''+table+''' where '''+field+''' = ?'''
    data = (value,)
    conn,cu = mitm_get_cur(DB_FILE_PATH)
    cu.execute(sql,data)
    r = cu.fetchall()
    close_all(conn,cu)
    return r
#获得最近的头信息
def mitm_get_headers_by_system_name(table,systemName):
    rows = mitm_select_max_data(table,"system_name",systemName,"headers")
    result = {}
    if table == 'mitmhttp':
        if len(rows)>0:
            for r in rows:
                result = eval(r[0])
    elif table == 'mitm_rep_info':
        if len(rows)>0:
            for r in rows:
                result = eval(r[0])
    return result
#多条件查询
def mitm_select_data_more_contidon_filter(table,fields:dict,compare,logic):
    try:
        base_sql = '''select * from '''+table+''' where '''
        condition = ''
        count = 0
        space = ' '
        data = []
        for k,v in fields.items():
            if count > 0:
                condition += space+logic +space
            condition += k +space+compare+space+ '?'
            count += 1
            data.append(v)
        data = tuple(data)
        base_sql += condition
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(base_sql,data)
        r = cu.fetchall()
        if len(r) > 0 :
            for e in range(len(r)):
                print(r[e])
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        print(base_sql)
        close_all(conn,cu)
#得到数据库的表信息
def get_sqlite_tables():
    conn,cu = mitm_get_cur(DB_FILE_PATH)
    cu.execute("select name from sqlite_master where type='table'")
    tab_name=cu.fetchall()
    tab_name=[line[0] for line in tab_name]
    return tab_name
#重置表自增列:
def mitm_reset_autoid(table):
    try:
        sql = "UPDATE sqlite_sequence SET seq = 0 WHERE name = \'"+table+"\'"
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
def main():
    testD = {
        "cookie":{"jessiod":"ddddddd"},
        "auth":"dssdfsdfsdf"
    }
    jsonD = json.dumps(testD)
    dataDict = {
        'name':'post',
        'headers':jsonD,
        "create_time":"123456"
    }
    #mitm_add_field('mitmhttp','is_response','integer')
    #mitm_show_table_field('mitmhttp')
    #mitm_show_table_field('mitm_rep_info')
    #drop_table_mitm('mitm_rep_info')
    #create_table_mitm()
    #request = mitm_select_data_filter('mitmhttp','system_name','localhost')
    #print(request[0]['headers'])
    #result = mitm_get_headers_by_system_name('mitmhttp',"localhost")
    #print(type(result))
    #headers = str(request['headers']).replace("'",'''"''')
    #print(headers)
    #result = json.loads(headers)
    #result = eval(headers)
    #print(result['content-type'])
    #create_table_mitm_rep_info()
    #mitm_insert_data_rep_info(dataDict)
    #result = mitm_select_all("mitmhttp")
    #for i in result:
        #print(i['url'])
    #mitm_del_data_all('mitmhttp')
    #import base64
    #print(str(base64.b64decode('Z3Vlc3Q6Z3Vlc3Q='),encoding='utf-8'))
    print(mitm_show_table_field('mitmhttp'))
if __name__ == '__main__':
    main()