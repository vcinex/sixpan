import base64
import hashlib
import hmac
import json
import random
import string
import time
import urllib
from collections import OrderedDict

import requests


class SixPan(object):
    def __init__(self, host, token, appid, secret):
        self.__host = host
        self.__token = token
        self.__appid = appid
        self.__secret = secret
        self.schema = 'https'

    def get_host(self):
        return self.__host

    def set_host(self, host):
        self.__host = host
        return True

    def get_token(self):
        return self.__token

    def set_token(self, token):
        self.__token = token
        return True

    def get_appid(self):
        return self.__appid

    def set_appid(self, appid):
        self.__appid = appid
        return True

    def get_secret(self):
        return self.__secret

    def set_secret(self, secret):
        self.__secret = secret
        return True

    def __sign(self, data, path, params):
        # 准备CanonicalizedHeaders和content-md5
        data_string = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        data_md5 = hashlib.md5(data_string.encode('utf-8')).hexdigest()
        # 准备appid ts和nonce
        params['appid'] = self.__appid
        params['nonce'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        params['ts'] = int(time.time())
        params = OrderedDict(sorted(params.items(), key=lambda t: t[0]))

        string1 = 'authorization: Bearer ' + self.__token + 'content-md5: ' + data_md5
        string2 = urllib.parse.urlencode(params)
        string3 = 'POST' + self.__host + path + '?' + string2 + string1

        key = bytes(self.__secret, 'utf-8')
        msg = bytes(string3, 'utf-8')
        signature = base64.b64encode(bytes(hmac.new(key=key, msg=msg, digestmod='sha256').hexdigest(), 'utf-8'))
        return signature

    def test_signature(self):
        data = {"accessKeySecret": "长者", "birthday": "19260817"}
        path = '/v3/system/sign'
        params = {'play': '夏威夷吉他', 'language': '八国语言', 'long': 'yes'}
        signature = self.__sign(data=data, path=path, params=params)
        return signature

    def get_privacy(self):
        path = '/v3/user/privacy'
        url = self.schema + '://' + self.__host + path
        r = requests.get(url)
        if r.status_code == 200:
            return r.text
        else:
            return False


client = SixPan('api.6pan.cn', token='tank1989', appid='董先生', secret='张宝华')
print(client.get_privacy())
print(client.test_signature())
