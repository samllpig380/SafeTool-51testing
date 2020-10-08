# SafeTool-51testing
51testing首发_安全测试工具
#### 介绍
51testing测试圈,安全测试工具<br>
本项目首发51testing测试圈<br>
地址:[quan.51testing.com/pcQuan/lecture/97](http://quan.51testing.com/pcQuan/lecture/97)<br>
博客地址：http://quan.51testing.com/pcQuan/owner/482?name=小猪<br>
码云地址：https://gitee.com/samllpig/SafeTool-51testing<br>
#### 软件架构
![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/%E7%B3%BB%E7%BB%9F%E6%9E%B6%E6%9E%84.png)
#### 20200920 V1.2版本更新内容
1. 请求拦截功能<br>
![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/intercept01.gif)<br>

2. 响应拦截功能<br>
![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/intercept02.gif)<br>
#### 20200907 V1.1版本更新内容
1. 数据重放功能<br>
![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/1.gif)<br>
2. 集成sqlmap，用于SQL注入测试<br>

![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/2.gif)<br>

![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/3.gif)<br>
3. 集成Hydra，hydra是黑客组织thc的一款开源密码攻击工具，用来测试存在暴力破解的漏洞，功能十分强大，支持多种协议的破解。<br>

![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/hydra01.png)<br>


![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/hydra02.png)<br>

![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/hydra03.png)<br>

![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/hydra04.png)<br>

![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/hydra05.png)<br>

4. 监控https流量，需要在cmd命令行窗口中输入mitmdump命令，在windows系统中生成ca证书，然后在当前用户的目录下找到相关系统的证书导入即可<br>

![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/zsh.png)<br>

5. 代码中取消了url的限制
#### 安装教程

1.  安装 python 3.6 环境
2.  安装 redis 
3.  安装 wxPython == 4.0.7
4.  pip install -r requirements.txt

#### 使用说明

1.  启动redis数据库
2.  启动服务端 myproxy.bat
3.  启动客户端 python consoleMain.py

#### 软件界面
![image](https://github.com/samllpig380/SafeTool-51testing/blob/master/png/gui.png)<br>

#### 作者说明
        作者： kail(小猪)
        (此程序会持续更新的功能，最终的目的是囊括大部分漏洞利用程序或测试方法，不局限于web安全测试)
        博客地址：http://quan.51testing.com/pcQuan/owner/482?name=小猪
        码云地址：https://gitee.com/samllpig/SafeTool-51testing
        历史文章:
        记性能测试经历中的一次疑难问题解决:http://quan.51testing.com/pcQuan/article/144
        记测试生涯中一次安全测试经历:http://quan.51testing.com/pcQuan/article/124
        畅想人工智能如何应用于测试，并写出分析原型:http://quan.51testing.com/pcQuan/lecture/52
        性能测试之师夷长技以自强:http://quan.51testing.com/pcQuan/lecture/8
        安全测试，独孤九剑:http://quan.51testing.com/pcQuan/lecture/64
        入门APP测试之思想框架:http://quan.51testing.com/pcQuan/lecture/72
