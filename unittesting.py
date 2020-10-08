import unittest
from config import config
from config import interceptConfig as ic
class test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        '''
        setUp函数之前运行，整个测试过程只执行一次
        是所有测试方法最先执行的
        '''
        pass
    def setUp(self):
        '''
        测试前的初始化工作，写在这里
        '''
        pass
    def test_get_mitm_intercept(self):
        conf = config()
        url = conf.get_intercept_url()
        req = conf.get_intercept_req()
        self.assertEqual(type(url),list)
        self.assertEqual(False,req)
    def test_get_intercept_all(self):
        conf = ic()
        self.assertEqual(type(conf.get_intercept()),list)
    def test_get_intercept_url_req(self):
        conf = ic()
        req = conf.get_intercept_url_req("test1")
        self.assertEqual(req['headers'],"test1_req_headers")
        self.assertEqual(req['params'],"test1_req_params")
    def test_get_intercept_url_resp(self):
        conf = ic()
        resp = conf.get_intercept_url_resp("test1")
        self.assertEqual(resp['headers'],"test1_resp_headers")
        self.assertEqual(resp['params'],"test1_resp_params")
    def test_get_mitm_intercept_set_url(self):
        conf = config()
        url = 'http://127.0.0.1:8080/WebGoat/attack?Screen=32&menu=5'
        conf.set_intercept_url(url)
    def test_set_intercept_url(self):
        conf = ic()
        url = 'http://127.0.0.1:8080/WebGoat/attack?Screen=32&menu=5'
        conf.set_intercept_url(url)
    def test_set_intercept_url_req_headers(self):
        conf = ic()
        url = 'http://127.0.0.1:8080/WebGoat/attack?Screen=32&menu=5'
        headers = "Cookie_JSESSIONID=45FCF83CD2DB1F0A223FFB738C8B3797"
        conf.set_intercept_url_req_headers(url,headers)
    def test_set_intercept_url_req_params(self):
        conf = ic()
        url = 'http://127.0.0.1:8080/WebGoat/attack?Screen=32&menu=5'
        params = "Screen=32&menu=5"
        conf.set_intercept_url_req_params(url,params)
    def test_set_intercept_url_resp_headers(self):
        conf = ic()
        url = 'http://127.0.0.1:8080/WebGoat/attack?Screen=32&menu=5'
        headers = "Server_Apache-Coyote/1.1"
        conf.set_intercept_url_resp_headers(url,headers)
    def test_set_intercept_url_resp_params(self):
        conf = ic()
        url = 'http://127.0.0.1:8080/WebGoat/attack?Screen=32&menu=5'
        params = "head"
        conf.set_intercept_url_resp_params(url,params)
    def tearDown(self):
        '''
        测试之前完成后的清理工作
        '''
        pass
    @classmethod
    def tearDownClass(cls):
        '''
        在tearDown之后执行，整个测试过程只执行一次
        '''
        pass
if __name__ == "__main__":
    unittest.main()
