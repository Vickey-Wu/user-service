import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.utils import formataddr
from registration  import log


class Exmail(object):
    def __init__(self):
        self.access_token = self.__get_token()
        self.lg = log.Logger("./log/exmail_log.log",level="info")

    def __get_token(self):
        # reference: https://exmail.qq.com/qy_mng_logic/doc#10003
        corpid = 'xxxxxxxxx'
        corpsecret = 'xxxxxxxxxxxxxx'
        url = 'https://api.exmail.qq.com/cgi-bin/gettoken?corpid={}&corpsecret={}'.format(corpid, corpsecret)
        resp = json.loads(requests.get(url).text)
        return resp['access_token']

    def get_email(self, userid):
        url = 'https://api.exmail.qq.com/cgi-bin/user/get?access_token={}&userid={}'.format(self.access_token, userid)
        resp = json.loads(requests.get(url).text)
        self.lg.logger.info("get email detail: %s", resp)
        #print(resp)
        if resp['errmsg'] == 'userid not found' or resp['errmsg'] == 'system error':
            return False
        else:
            return True

    def create_email(self, sn, tel, mail, init_passwd):
        userid = mail
        name = sn
        mobile = tel
        userid = mail
        userid = mail
        data = {
               "userid": userid,
               "name": name,
               "department": [888888888888],	# default deptid
               "position": "",
               "mobile": mobile,
               "tel": "",
               "extid": "",
               "gender": "1",
               "slaves": [],
               "password": init_passwd,
               "cpwd_login": 1
               }
        url = 'https://api.exmail.qq.com/cgi-bin/user/create?access_token={}'.format(self.access_token)
        resp = json.loads(requests.post(url, data=json.dumps(data)).text)
        self.lg.logger.info("create email account info: %s", resp)
        if resp['errmsg'] == 'ok':
            self.lg.logger.info("email %s create successfully", userid)
            return True
        else:
            return False

    def delete_email(self, userid):
        url = 'https://api.exmail.qq.com/cgi-bin/user/delete?access_token={}&userid={}'.format(self.access_token, userid)
        resp = json.loads(requests.get(url).text)
        self.lg.logger.info("delete email account info: %s", resp)
        if resp['errmsg'] == 'ok':
            return True
        else:
            return False


#ex = Exmail()
#print(ex.get_email('xxxxxxxxxxx@vickey-wu.com'))
#ex.get_email('xxxxxxxxxxx@vickey-wu.com')
#ex.get_email('188888888888')
#ex.create_email('xxxxx', '188888888888', 'xxxxxxxx@vickey-wu.com', 'password')
#ex.delete_email('xxx@vickey-wu.com')
