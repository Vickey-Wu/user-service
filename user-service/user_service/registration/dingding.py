#!/usr/bin/python
# -*- coding: utf8 -*-
"""
# 发送消息到钉钉
"""
import json
import time
import requests


# dingidng notification
class Dingding(object):
    def __init__(self, access_token, content, at_people=''):
        self.access_token = access_token
        self.content = content
        self.at_people = at_people

    def get_token(self):
        '''
        钉钉管理后台 : http://open-dev.dingtalk.com
        '''
        access_token = 'https://oapi.dingtalk.com/robot/send?access_token=%s' % self.access_token
        return access_token
    
    def send_dingding(self):
        '''
        access_token: dingding机器人token
        content: 发送的内容
        msgtype : 类型
        '''
        #access_token, content, at_people
        msgtype = 'text'
        if self.at_people == '':
            values = {
                      'msgtype': 'text',
                      msgtype: {
                                'content': self.content
                      },
                      #'at': {
                      #        'atMobiles': ['188888888888','+86-1888888888'],
                      #},
            }
        else:
            values = {
                      'msgtype': 'text',
                      msgtype: {
                                'content': self.content
                      },
                      'at': {
                              'atMobiles': [self.at_people]
                      },
            }
    
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        values = json.dumps(values)
        res = requests.post(self.get_token(), values, headers=headers)
        errmsg = json.loads(res.text)['errmsg']
    
        if errmsg == 'ok':
            return 'ok'
    
        return 'fail: %s' % res.text
