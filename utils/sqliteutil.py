#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sqlite3
import os
import traceback
#global var
#数据库文件绝对路径
DB_PATH = os.path.join(os.getcwd(), "db")
DB_FILE_PATH = DB_PATH + "\\mitm.db"
#表名称
TABLE_NAME = ''
#是否打印sql
SHOW_SQL = True

def get_conn(path):
    '''获取到数据库的连接对象，参数为数据库文件的绝对路径
    如果传递的参数是存在，并且是文件，那么就返回硬盘上面改
    路径下的数据库文件的连接对象；否则，返回内存中的数据接
    连接对象'''
    conn = sqlite3.connect(path)
    if os.path.exists(path) and os.path.isfile(path):
        print('硬盘上面:[{}]'.format(path))
        return conn
    else:
        conn = None
        print('内存上面:[:memory:]')
        return sqlite3.connect(':memory:')

def get_cursor(conn):
    '''该方法是获取数据库的游标对象，参数为数据库的连接对象
    如果数据库的连接对象不为None，则返回数据库连接对象所创
    建的游标对象；否则返回一个游标对象，该对象是内存中数据
    库连接对象所创建的游标对象'''
    if conn is not None:
        return conn.cursor()
    else:
        return get_conn('').cursor()

###############################################################
####            创建|删除表操作     START
###############################################################
def drop_table(conn, table):
    '''如果表存在,则删除表，如果表中存在数据的时候，使用该
    方法的时候要慎用！'''
    if table is not None and table != '':
        sql = 'DROP TABLE IF EXISTS ' + table
        if SHOW_SQL:
            print('执行sql:[{}]'.format(sql))
        cu = get_cursor(conn)
        cu.execute(sql)
        conn.commit()
        print('删除数据库表[{}]成功!'.format(table))
        close_all(conn, cu)
    else:
        print('the [{}] is empty or equal None!')

def create_table(conn, sql):
    '''创建数据库表：student'''
    if sql is not None and sql != '':
        cu = get_cursor(conn)
        if SHOW_SQL:
            print('执行sql:[{}]'.format(sql))
        cu.execute(sql)
        conn.commit()
        print('创建数据库表成功!')
        close_all(conn, cu)
    else:
        print('the [{}] is empty or equal None!'.format(sql))

###############################################################
####            创建|删除表操作     END
###############################################################

def close_all(conn, cu):
    '''关闭数据库游标对象和数据库连接对象'''
    try:
        if cu is not None:
            cu.close()
    finally:
        if conn is not None:
            conn.close()

###############################################################
####            数据库操作CRUD     START
###############################################################

def save(conn, sql, data):
    '''插入数据'''
    if sql is not None and sql != '':
        if data is not None:
            cu = get_cursor(conn)
            for d in data:
                if SHOW_SQL:
                    print('执行sql:[{}],参数:[{}]'.format(sql, d))
                cu.execute(sql, d)
                conn.commit()
            close_all(conn, cu)
    else:
        print('the [{}] is empty or equal None!'.format(sql))

def fetchall(conn, sql):
    '''查询所有数据'''
    if sql is not None and sql != '':
        cu = get_cursor(conn)
        if SHOW_SQL:
            print('执行sql:[{}]'.format(sql))
        cu.execute(sql)
        r = cu.fetchall()
        if len(r) > 0:
            for e in range(len(r)):
                print(r[e])
    else:
        print('the [{}] is empty or equal None!'.format(sql))

def fetchone(conn, sql, data):
    '''查询一条数据'''
    if sql is not None and sql != '':
        if data is not None:
            #Do this instead
            d = (data,)
            cu = get_cursor(conn)
            if SHOW_SQL:
                print('执行sql:[{}],参数:[{}]'.format(sql, data))
            cu.execute(sql, d)
            r = cu.fetchall()
            if len(r) > 0:
                for e in range(len(r)):
                    print(r[e])
        else:
            print('the [{}] equal None!'.format(data))
    else:
        print('the [{}] is empty or equal None!'.format(sql))

def update(conn, sql, data):
    '''更新数据'''
    if sql is not None and sql != '':
        if data is not None:
            cu = get_cursor(conn)
            for d in data:
                if SHOW_SQL:
                    print('执行sql:[{}],参数:[{}]'.format(sql, d))
                cu.execute(sql, d)
                conn.commit()
            close_all(conn, cu)
    else:
        print('the [{}] is empty or equal None!'.format(sql))

def delete(conn, sql, data):
    '''删除数据'''
    if sql is not None and sql != '':
        if data is not None:
            cu = get_cursor(conn)
            for d in data:
                if SHOW_SQL:
                    print('执行sql:[{}],参数:[{}]'.format(sql, d))
                cu.execute(sql, d)
                conn.commit()
            close_all(conn, cu)
    else:
        print('the [{}] is empty or equal None!'.format(sql))
###############################################################
####            数据库操作CRUD     END
###############################################################


###############################################################
####            测试操作     START
###############################################################
def drop_table_test():
    '''删除数据库表测试'''
    print('删除数据库表测试...')
    conn = get_conn(DB_FILE_PATH)
    drop_table(conn, TABLE_NAME)

def create_table_test():
    '''创建数据库表测试'''
    print('创建数据库表测试...')
    create_table_sql = '''CREATE TABLE `recordtest` (
                          `caseid` integer PRIMARY KEY autoincrement,
                          `http_method` varchar(20) NOT NULL,
                          `request_name` varchar(200) DEFAULT NULL,
                          `request_url` varchar(4) DEFAULT NULL,
                          `request_param` varchar(1000) DEFAULT NULL,
                          `test_method` varchar(10) DEFAULT NULL,
                          `test_desc` varchar(1000) DEFAULT NULL,
                          `result` varchar(1000) DEFAULT NULL,
                          'reason' varchar(1000) DEFAULT NULL
                        )'''
    conn = get_conn(DB_FILE_PATH)
    create_table(conn, create_table_sql)
def save_record(ds):
    '''保存数据测试...'''
    print('保存数据测试...')
    save_sql = '''INSERT INTO recordtest(http_method,request_name,request_url,request_param,test_method,test_desc,result,reason) values (?, ?,?, ?, ?, ?,?,?)'''
    data = [(ds.http_method,ds.request_name, ds.request_url, ds.request_param, ds.test_method,ds.test_desc, ds.result,ds.reason)]
    conn = get_conn(DB_FILE_PATH)
    save(conn, save_sql, data)

def fetchall_test():
    '''查询所有数据...'''
    print('查询所有数据...')
    fetchall_sql = '''SELECT * FROM student'''
    conn = get_conn(DB_FILE_PATH)
    fetchall(conn, fetchall_sql)

def fetchone_test():
    '''查询一条数据...'''
    print('查询一条数据...')
    fetchone_sql = 'SELECT * FROM student WHERE ID = ? '
    data = 1
    conn = get_conn(DB_FILE_PATH)
    fetchone(conn, fetchone_sql, data)

def update_test():
    '''更新数据...'''
    print('更新数据...')
    update_sql = 'UPDATE student SET name = ? WHERE ID = ? '
    data = [('HongtenAA', 1),
            ('HongtenBB', 2),
            ('HongtenCC', 3),
            ('HongtenDD', 4)]
    conn = get_conn(DB_FILE_PATH)
    update(conn, update_sql, data)

def delete_test():
    '''删除数据...'''
    print('删除数据...')
    delete_sql = 'DELETE FROM student WHERE NAME = ? AND ID = ? '
    data = [('HongtenAA', 1),
            ('HongtenCC', 3)]
    conn = get_conn(DB_FILE_PATH)
    delete(conn, delete_sql, data)
###############################################################
####            mitm表操作     START
###############################################################
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
                        )'''
    conn = get_conn(DB_FILE_PATH)
    create_table(conn, create_table_sql)
#得到游标数据
def mitm_get_cur(path):
    conn = get_conn(path)
    cu = get_cursor(conn)
    return conn,cu
#增加字段
def mitm_add_field(table,field,fieldType):
    try:
        add_sql = '''ALTER TABLE `'''+table + '''`ADD COLUMN `'''+field+'''`'''+fieldType+'''DEFAULT NULL'''
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
        if len(r)>0:
            for e in range(len(r)):
                print(r[e])
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
#插入数据
def mitm_insert_data(dataDict):
    try:
        sql = '''INSERT INTO mitmhttp(method,url,headers,params,create_time,system_name) values (?, ?,?, ?, ?,?)'''
        data = (dataDict['method'],dataDict['url'],dataDict['headers'],dataDict['params'],dataDict['create_time'],dataDict['system_name'])
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql,data)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)

def mitm_del_data_all():
    try:
        sql = '''delete from mitmhttp'''
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)

def mitm_del_data_filter(field,value):
    try:
        sql = '''delete from mitmhttp where '''+field+''' = ?'''
        data = (value,)
        conn,cu = mitm_get_cur(DB_FILE_PATH)
        cu.execute(sql,data)
        conn.commit()
        close_all(conn,cu)
    except Exception as e:
        print(traceback.print_exc())
        close_all(conn,cu)
#按条件查询
def mitm_select_data_filter(field,value):
    sql = '''select * from mitmhttp where '''+field+''' = ?'''
    data = (value,)
    conn,cu = mitm_get_cur(DB_FILE_PATH)
    cu.execute(sql,data)
    r = cu.fetchall()
    if len(r)>0:
        for e in range(len(r)):
            print(r[e])
    close_all(conn,cu)
#多条件查询
def mitm_select_data_more_contidon_filter(fields:dict,compare,logic):
    try:
        base_sql = '''select * from mitmhttp where '''
        condition = ''
        count = 0
        space = ' '
        data = []
        for k,v in filter.items():
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
    

###############################################################
####            测试操作     END
###############################################################

def init():
    '''初始化方法'''
    #数据库表名称
    global TABLE_NAME
    TABLE_NAME = 'recordtest'
    #是否打印sql
    global SHOW_SQL
    SHOW_SQL = True
    print('show_sql : {}'.format(SHOW_SQL))
    #如果存在数据库表，则删除表
    drop_table_test()
    #创建数据库表student
    create_table_mitm()
    #向数据库表中插入数据
   # save_test()


def main():
    dataDict = {
        'method':'post',
        'url':'www.test.com',
    }
    #(1, 'post', 'www.test.com', 'xxxx', 'a=11&b=ss', '1111111', 'test')
    #for k,v in dataDict.items():
        #print(k)
        #print(v)
    #mitm_select_data_more_contidon_filter(dataDict,'=','and')
    mitm_del_data_filter('ID',1)
    #mitm_insert_data(dataDict)
    #mitm_select_data_filter('id','1')
    #init()
    #mitm_add_field('mitmhttp','system_name','varchar(100)')
    #mitm_show_table_field('mitmhttp')
    #fetchall_test()
    #print('#' * 50)
    #fetchone_test()
    #print('#' * 50)
    #update_test()
    #fetchall_test()
    #print('#' * 50)
    #delete_test()
    #fetchall_test()
    pass
if __name__ == '__main__':
    main()