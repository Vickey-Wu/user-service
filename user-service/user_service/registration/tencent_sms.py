#!/usr/bin/python
# -*- coding: utf-8 -*-

from qcloudsms_py import SmsSingleSender
from qcloudsms_py.httpclient import HTTPError
from registration  import log
from django.conf import settings as sms_setting
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "user_registration.settings")


class Sms(object):
    def __init__(self):
        # Enum{0: 普通短信, 1: 营销短信}
        self.lg = log.Logger("./log/tencent_sms.log",level="info")
        self.sms_type = 0
        self.appid = sms_setting.APPID
        self.appkey = sms_setting.APPKEY

    def send_sms(self, phone, mail):
        # 仅发送短信给单个用户
        msg = 'test content'.format(mail)
        if isinstance(phone, int):
            phone = str(phone)
        ssender = SmsSingleSender(self.appid, self.appkey)

        try:
            # 
            result = ssender.send(self.sms_type, 86, phone, msg, extend="", ext="")
        except HTTPError as e:
            print(e)
            self.lg.logger.info("Sms class HTTPError: %s", e)
        except Exception as e:
            print(e)
            self.lg.logger.info("Sms class Exception: %s", e)
        print('Sms send result:', result['errmsg'])
        self.lg.logger.info("Sms send result: %s", result)
        return result['errmsg']
