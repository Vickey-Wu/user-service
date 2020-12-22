# -*- coding: utf-8 -*-
#import dingtalk.api
import json
import requests
import re


def get_token():
    corpid="dingxxxxxxxxxx"
    corpsecret="xxxxxxxxxxxxxx"
    url = "https://oapi.dingtalk.com/gettoken?appkey={}&appsecret={}".format(corpid, corpsecret)
    resp = json.loads(requests.get(url).text)
    return resp['access_token']


def register_callback(access_token):

    url = 'https://oapi.dingtalk.com/call_back/register_call_back?access_token={}'.format(access_token)
    data = {
        "call_back_tag": ["bpms_task_change", "bpms_instance_change"],  	#这两个回调种类是审批的
        "token": 'xxxxxxxxxxxxx',  						#自定义的字符串
        "aes_key": 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 		#自定义的43位字符串，密钥
        "url": 'https://vickey-wu.com:8888/dingding/'  				#回调地址
    }
    resp = requests.post(url, data=json.dumps(data))
    print(resp.text)


if __name__ == '__main__':
    access_token = get_token()
    #print(access_token)
    #仅需注册一次
    register_callback(access_token)
