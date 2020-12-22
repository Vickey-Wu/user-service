# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import re
import requests
import json
import time
from django.shortcuts import render
from django.forms import model_to_dict
from django.shortcuts import render, redirect, HttpResponse
from django.http import HttpResponseRedirect, JsonResponse
from django.contrib import auth
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.http import urlquote
from . import models, log, dingding, check, ldap3_add_user, tencent_sms, keycloak_role, exmail
from . import mail as em
from pypinyin import lazy_pinyin
from .dingtalk.callback import crypto


lg = log.Logger('./log/view_log.log',level='debug')
ld = ldap3_add_user.Ldap3()
ck = check.Check()
sms = tencent_sms.Sms()
BOT_TOKEN = 'xxxxxxxxxxxxxxxxx'


def dingding_access_token():
    corpid="dingxxxxxxxxxxx"
    corpsecret="xxxxxxxxxxxxxxxx"
    url = "https://oapi.dingtalk.com/gettoken?appkey={}&appsecret={}".format(corpid, corpsecret)
    resp = json.loads(requests.get(url).text)
    return resp['access_token']


def register_callback(access_token):

    url = 'https://oapi.dingtalk.com/call_back/register_call_back?access_token={}'.format(access_token)
    #print(url)
    data = {
        "call_back_tag": ["bpms_task_change", "bpms_instance_change"],          #这两个回调种类是审批的
        "token": 'xxxxxxxxxxxxxx',                                            #自定义的字符串
        "aes_key": 'xxxxxxxxxxxx',               #自定义的43位字符串，密钥
        "url": 'http://vickey-wu:8000/dingding/'                            #回调地址
    }
    resp = requests.post(url, data=json.dumps(data))
    lg.logger.info("register_callback result: %s" % resp.text)


def add_authorities(instance_detail, sn, group, realm, role, ldap_group=None, additiaonal=False):
    role_map_authority = {'查看权限': ['view', 'ldap-group-name1'],
                          '编辑权限': ['edit', 'ldap-group-name2'],
                          '其他权限': [None, None]}
    realm_ldap_map = {'ldap-group-name1': 'ldap-group-name1-users',
                      'ldap-group-name22': 'ldap-group-name2-users'}

    authority_raw = instance_detail['process_instance']['form_component_values'][1]['value']
    authority_raw = authority_raw.replace('[','').replace(']','').replace('"','').split(',')
    lg.logger.info('authorities are {}'.format(authority_raw))
    if len(authority_raw) == 1 and role_map_authority.get(authority_raw[0])[0] is None:
        # 6. 如果权限为'其他'，查询keycloak无相应权限则钉钉提醒管理员手动添加
        # send dingding
        content = '用户{}申请的权限为{}，自动添加权限失败，请手动添加权限，如果是新注册用户则忽略'.format(sn, authority_raw)
        ding = dingding.Dingding(BOT_TOKEN, content)
        ding.send_dingding()
    else:
        # 5.1. 根据用户所在部门不同，不同realm，加入不同的ldap分组
        if ldap_group is not None:
            ld.ldap_add_authority(sn, group, ldap_group, additiaonal)
            keycloak_role.add_realm_role_to_user(sn, realm, role)
        else:
            for a in authority_raw:
                role = role_map_authority.get(a)[0]
                ldap_group = realm_ldap_map.get(role_map_authority.get(a)[1])
                # 5.1. 根据用户所在部门不同，不同realm，加入不同的ldap分组
                ld.ldap_add_authority(sn, group, ldap_group, additiaonal)
                lg.logger.info('single authority is {}'.format(a))
                if role is not None:
                    time.sleep(5)
                    # 5.2. 根据需要的权限为用户在keycloak加入相应role
                    keycloak_role.add_realm_role_to_user(sn, role_map_authority.get(a)[1], role)
                    lg.logger.info('add keycloak role "{}" successfully'.format(role))


def get_dingding_userid(access_token, sn):
    search_resp = get_user_mobile(sn, 'sn')
    lg.logger.info('get user mobile: {}'.format(search_resp))
    mobile = search_resp['mobile']
    url = "https://oapi.dingtalk.com/user/get_by_mobile?access_token={}&mobile={}".format(access_token, mobile)
    resp = json.loads(requests.get(url).text)
    lg.logger.info('dingding userid resp: {}'.format(resp))
    return resp['userid']


def get_dingding_user_info(access_token, userid):
    #url = "https://oapi.dingtalk.com/user/getUseridByUnionid?access_token={}&unionid={}".format(access_token, unionid)
    url = "https://oapi.dingtalk.com/user/get?access_token={}&userid={}".format(access_token, userid)
    #print(url)
    resp = requests.get(url)
    return resp.text
    #print(resp.text)
 

def create_approval_instance(access_token, userid, data):
    ## e.g: https://aflow.dingtalk.com/dingtalk/web/query/designCenter?formUuid=FORM-xxxxxxxxxxxxxxxxxxxxx&processCode=PROC-xxxxxxxxxxxxxxxxxxxx&processStatus=INVALID&v=2&from=custom&corpId=dingxxxxxxxxxxx&tab=global&dirId=other
    url = "https://oapi.dingtalk.com/topapi/processinstance/create?access_token={}".format(access_token)
    lg.logger.info("submit data are: %s, %s" % (type(data), data))

    # user info
    user_info = get_dingding_user_info(access_token, userid)
    user_info = json.loads(user_info)
    dept_id = str(user_info[u'department'][0])

    # component info
    component_dict = {'网址1': data['url'], '申请备注': data['remark']}
    form_component_values = [{'component_type': 'TextField', 'value': component_dict['网址1'], 'id': 'TextField-xxxxxxxxxx', 'name': '网址1'}, {'component_type': 'TextField', 'value': 'null', 'id': 'TextField-xxxxxxxxxx', 'name': '网址2'}, {'component_type': 'TextField', 'value': 'null', 'id': 'TextField-xxxxxxxxx', 'name': '网址3'}, {'component_type': 'TextareaField', 'value': component_dict['申请备注'], 'id': 'TextareaField-xxxxxxxxxxxxxx', 'name': '申请备注'}]
    data = {
        "process_code": 'PROC-xxxxxxxxxxxxxxxxxxx',
        "originator_user_id": userid,
        "dept_id": dept_id,
        "form_component_values": form_component_values

    }
    resp = requests.post(url, data=json.dumps(data))
    lg.logger.info("dingding create instance response is: %s, %s" % (type(resp), resp))


def delete_content(need_delete_url):
    if 'http' not in need_delete_url:
        lg.logger.info("ignore none url value: %s, %s" % (type(need_delete_url), need_delete_url))
        pass
    else:
        url_id = re.findall('/\d+', need_delete_url)[-1].replace('/', '')
        data = {"id": url_id}
        ## default test server
        server_url = "https://test.vickey-wu.com:8080"
        #req_token = keycloak_role.get_keycloak_token()
        req_token = keycloak_role.get_keycloak_token(realm='vickey-wu-test')
        api_url = None
        if '//www.vickey-wu.com' in need_delete_url or '//m.vickey-wu.com' in need_delete_url:
            server_url = "https://www.vickey-wu.com:8081"
            req_token = keycloak_role.get_keycloak_token(realm='vickey-wu-test')
        headers = {'Content-Type':'application/json', 'Authorization': 'Bearer %s' % req_token}
        lg.logger.info("keycloak token headers is: %s" % headers)
    
        if '/live/' in need_delete_url:
            api_url = '{}/api/admin/live/delete'.format(server_url)
            lg.logger.info("delete live: %s, %s" % (type(need_delete_url), need_delete_url))
        elif '/news/' in need_delete_url:
            api_url = '{}/api/admin/news/{}/delete'.format(server_url, url_id)
            lg.logger.info("delete news: %s, %s" % (type(need_delete_url), need_delete_url))
        elif '/p/' in need_delete_url:
            api_url = '{}/api/admin/post/batUpdateStatus'.format(server_url)
            data = {"ids": [url_id], "status": 0}
            lg.logger.info("delete article: %s, %s" % (type(need_delete_url), need_delete_url))
        else:
            lg.logger.info("dingding delete content url not matched api rule! pass!")
            pass

        resp = requests.post(api_url, data=json.dumps(data), headers=headers)
        lg.logger.info("delete content result: %s, %s" % (type(resp.text), resp.text))


def ding_delete_content_approval(request):
    if request.method == 'POST':
        response = json.loads(request.body.decode())
        #todo: check_response()
        lg.logger.info("dingding response is: %s, %s" % (type(response), response))
        sn = response['username']
        access_token = dingding_access_token()
        userid = get_dingding_userid(access_token, sn)
        lg.logger.info("dingding userid is: %s, %s" % (type(userid), userid))
        create_approval_instance(access_token, userid, response)
        #return_resp = json.dumps({"status": "ok"})
        return_resp = {"statusCode":200,"message":"","totalCount":0,"result": ""}
        lg.logger.info("dingding delete content response is: %s, %s" % (type(return_resp), return_resp))
        return JsonResponse(return_resp)
    else:
        return HttpResponse('Not support')


def ding_approval(request):
    if request.method == 'POST':

        token = 'xxxxxxxxxx'
        aes_key = 'xxxxxxxxxxxxx'
        corpid = 'xxxxxxxxxx'		# corpid

        response = request.body.decode()
        lg.logger.info("dingding response is: %s, %s" % (type(response), response))
        encrypt_msg = json.loads(response)['encrypt']
        msg = json.loads(crypto.decrypt(aes_key, encrypt_msg)[0])

        #### 根据类型返回不同不同方法处理
        ## 注册回调时用到的响应
        if msg['EventType'] == 'check_url':
            success_msg = crypto.encrypt(aes_key, 'success', corpid).decode()
            timestamp = str(int(time.time()*1000))
            nonce = 'randomword'
            lg.logger.info("type is: %s, %s, %s, %s" % (type(token), type(success_msg),type(timestamp),type(nonce)))
            msg_signature = crypto.generate_callback_signature(token, success_msg, timestamp, nonce)
            success_dict = {
                           "encrypt": success_msg,			# 'success'字符串加密后的字符串(不能是bytes类型)
                           "msg_signature": msg_signature,		# encrypt字段的签名
                           "timeStamp": timestamp,			# 当前时间戳
                           "nonce": nonce				# 随便设置个随机字符串
                           }
            success_json = json.dumps(success_dict)			# 返回给钉钉的json数据
            return HttpResponse(success_json)

        #### dingding delete user and exmail
        elif msg['EventType'] == 'bpms_instance_change' \
        and msg['processCode'] == 'PROC-11111111111111' \
        and msg['type'] == 'finish':
            process_instance_id = msg['processInstanceId']
            access_token = dingding_access_token()
            instance_detail = json.loads(get_instance_detail(access_token, process_instance_id))
            lg.logger.info("instance detail is: %s, %s" %  (type(instance_detail), instance_detail))
            approval_result = instance_detail['process_instance']['result']
            lg.logger.info("approval_result is: %s" %  approval_result)
            if approval_result == 'agree':
                userid = instance_detail['process_instance']['originator_userid']
                lg.logger.info("user id is: %s, %s" %  (type(userid), userid))
                user_detail = json.loads(get_user_detail(access_token, userid))
                lg.logger.info("user detail is: %s, %s" %  (type(user_detail), user_detail))
                cn = user_detail['name'].replace(" ", "")
                sn = chinese_to_pinyin(cn)
                lg.logger.info('cn: {}'.format(cn))
                # 1. 如果审批结束，查看ldap是否有该用户账号, 有则直接删除，无则忽略
                search_resp = ld.ldap_search_user(sn, 'sn')
                lg.logger.info("sn is: %s, %s" %  (sn, search_resp))
                if search_resp != []:
                    # 删除用户账户
                    lg.logger.info('in delete account process')
                    delete_status = ld.ldap_delete_user(sn)
                    if delete_status and delete_status == 'success':
                        lg.logger.info('用户%s账号已删除！' % sn)
                    else:
                        lg.logger.info('用户%s账号删除失败！' % sn)
                        content = '用户{}账号删除失败！请人工确认是否删除'.format(sn)
                        ding = dingding.Dingding(BOT_TOKEN, content)
                        ding.send_dingding()
                else:
                    lg.logger.info('用户%s无后台账号无需删除' % sn)
                # 2. 如果审批结束，查看email是否有该用户账号, 有则直接删除，无则忽略
                ex =  exmail.Exmail()
                exsited_email =  ex.get_email(sn + '@vickey-wu.com')
                if exsited_email:
                    lg.logger.info('in delete email process')
                    delete_status = ex.delete_email(sn + '@vickey-wu.com')
                    if delete_status:
                        lg.logger.info("已删除用户%s的vickey-wu.com邮箱" % sn)
                    else:
                        lg.logger.info('用户%s邮箱删除失败！' % sn)
                        content = '用户{}的vickey-wu.com邮箱删除失败！请人工确认是否删除'.format(sn)
                        ding = dingding.Dingding(BOT_TOKEN, content)
                        ding.send_dingding()
                else:
                    lg.logger.info("用户%s没有vickey-wu.com的邮箱" % sn)
            return HttpResponse('delete user and exmail approval finished')

        #### dingding delete content
        ## 删除内容审批实例完成时需要执行的操作
        elif msg['EventType'] == 'bpms_instance_change' \
        and msg['processCode'] == 'PROC-222222222222' \
        and msg['type'] == 'finish':
            process_instance_id = msg['processInstanceId']
            access_token = dingding_access_token()
            instance_detail = json.loads(get_instance_detail(access_token, process_instance_id))
            lg.logger.info("delete content instance detail is: %s, %s" %  (type(instance_detail), instance_detail))
            approval_result = instance_detail['process_instance']['result']
            lg.logger.info("approval_result is: %s" %  approval_result)
            if approval_result == 'agree':
                all_url = instance_detail['process_instance']['form_component_values']
                lg.logger.info("all_url is: %s, %s" %  (type(all_url), all_url))
                for url_value in all_url:
                    need_delete_url = url_value['value']
                    delete_content(need_delete_url)
                    lg.logger.info("test delete content: %s" % need_delete_url)
            return HttpResponse('delete content approval finished')

        #### dingding add authorities only
        elif msg['EventType'] == 'bpms_instance_change' \
        and msg['processCode'] == 'PROC-3333333333333333' \
        and msg['type'] == 'finish':
            process_instance_id = msg['processInstanceId']
            access_token = dingding_access_token()
            instance_detail = json.loads(get_instance_detail(access_token, process_instance_id))
            lg.logger.info("instance detail is: %s, %s" %  (type(instance_detail), instance_detail))
            approval_result = instance_detail['process_instance']['result']
            lg.logger.info("approval_result is: %s" %  approval_result)
            if approval_result == 'agree':
                userid = instance_detail['process_instance']['originator_userid']
                lg.logger.info("user id is: %s, %s" %  (type(userid), userid))
                user_detail = json.loads(get_user_detail(access_token, userid))
                lg.logger.info("user detail is: %s, %s" %  (type(user_detail), user_detail))
                cn = user_detail['name'].replace(" ", "")
                sn = chinese_to_pinyin(cn)
                tel = user_detail['mobile']
                group = instance_detail['process_instance']['originator_dept_name']
                lg.logger.info('cn: {}, sn:{}, tel:{}, group:{}'.format(cn, sn, tel, group))

                # 1. 如果审批结束，查看ldap是否已注册该用户, 有则直接添加相应权限, 无则不做处理，钉钉提示先注册用户
                search_resp = ld.ldap_search_user(sn, 'sn')
                lg.logger.info("sn is: %s, %s" %  (sn, search_resp))
                authority_raw = instance_detail['process_instance']['form_component_values'][1]['value']
                lg.logger.info('authorities are {}'.format(authority_raw))
                if search_resp != []:
                    ## 申请额外权限
                    add_authorities(instance_detail, sn, group, realm=None, role=None, ldap_group=None, additiaonal=False)
                else:
                    lg.logger.info('该用户未注册账号，无法申请权限')
                    content = '用户{}申请的权限:{}，但该用户未注册账号，无法申请权限，请救救他'.format(sn, authority_raw)
                    ding = dingding.Dingding(BOT_TOKEN, content)
                    ding.send_dingding()

            return HttpResponse('delete content approval finished')

        #### dingding register and add authorities
        ## 注册或添加权限审批实例完成时需要执行的操作
        # 1. 如果审批结束，查看ldap是否已注册该用户, 有则直接添加相应权限
        # 2. 未注册则查看该用户手机号是否有注册'姓名全拼@vickey-wu.com'的企业邮箱，无则注册邮箱
        # 3. 从钉钉返回数据拿到该用户的手机号，姓名，结合刚注册的邮箱注册ldap账号
        # 4. 注册账号后，加入ldap的test组
        # 5. 根据需要的权限为用户在keycloak加入相应role，会员管理权限加入ldap的test组即可，不需要加role
        # 6. 如果权限为'其他'，查询keycloak无相应权限则钉钉提醒管理员手动添加

        elif msg['EventType'] == 'bpms_instance_change' \
        and msg['processCode'] == 'PROC-44444444444' \
        and msg['type'] == 'finish':
            process_instance_id = msg['processInstanceId']
            access_token = dingding_access_token()
            instance_detail = json.loads(get_instance_detail(access_token, process_instance_id))
            lg.logger.info("instance detail is: %s, %s" %  (type(instance_detail), instance_detail))
            approval_result = instance_detail['process_instance']['result']
            lg.logger.info("approval_result is: %s" %  approval_result)
            if approval_result == 'agree':
                userid = instance_detail['process_instance']['originator_userid']
                lg.logger.info("user id is: %s, %s" %  (type(userid), userid))
                user_detail = json.loads(get_user_detail(access_token, userid))
                lg.logger.info("user detail is: %s, %s" %  (type(user_detail), user_detail))
                cn = user_detail['name'].replace(" ", "")
                sn = chinese_to_pinyin(cn)
                tel = user_detail['mobile']
                group = instance_detail['process_instance']['originator_dept_name']
                lg.logger.info('cn: {}, sn:{}, tel:{}, group:{}'.format(cn, sn, tel, group))

                # 1. 如果审批结束，查看ldap是否已注册该用户, 有则直接添加相应权限
                search_resp = ld.ldap_search_user(sn, 'sn')
                lg.logger.info("sn is: %s, %s" %  (sn, search_resp))
                if search_resp == []:
                    # 2. 未注册则查看该用户是否有注册'姓名全拼@vickey-wu.com'的企业邮箱，无则注册邮箱
                    new_email =  sn + '@vickey-wu.com'
                    random_password = ld.random_passwd()
                    time.sleep(3)
                    lg.logger.info('random_password is : {}'.format(random_password))
                    ex =  exmail.Exmail()
                    exsited_email =  ex.get_email(sn + '@vickey-wu.com')
                    if exsited_email:
                        new_email =  sn + '1@vickey-wu.com'
                    is_create_success = ex.create_email(cn, tel, new_email, random_password)
                    time.sleep(5)
                    lg.logger.info('create email status: {}'.format(is_create_success))
                    if is_create_success:
                        # 3. 从钉钉返回数据拿到该用户的手机号，姓名，结合刚注册的邮箱注册ldap账号, 注册时会根据部门添加到对应默认ldap分组
                        add_status = ld.ldap_add_user(cn, sn, new_email, tel, group, random_password)
                        lg.logger.info("create ldap user info: cn:{}, sn:{}, new_email:{}, tel:{}, group:{}, random_passwd:{}".format(cn, sn, new_email, tel, group, random_password))
                        if add_status == 'success':
                            time.sleep(5)
                            send_note(tel, new_email, random_password)
                            lg.logger.info('add user successsssss')
                            # 4. 注册账号后，根据部门添加不同的默认权限。如：内容中心加入editor权限
                            dep_dict = {
                                       1:'研发中心',
                                       2:'研究中心',
                                       }
                            else:
                                lg.logger.info("{} 新用户 '{}' 暂时不需要添加默认权限".format(group, cn))
                    else: 
                        lg.logger.info('可能用户已有邮箱导致创建邮箱失败，请手动完成账号注册流程')
                        # send dingding
                        content = '你好，新用户%s创建失败，请及时查看' % cn
                        at_people = ''
                        ding = dingding.Dingding(BOT_TOKEN, content, at_people)
                        lg.logger.info('{},{},{}'.format(access_token, content, at_people))
                        ding.send_dingding()
                        lg.logger.info('已发送通知')
                else:
                    lg.logger.info('已存在该用户，无需注册')

            return HttpResponse('nice to meet you')
        else:
            return HttpResponse('nice to meet you')
    else:
        return HttpResponse('not support!')


def get_instance_detail(access_token, process_instance_id):
    url = 'https://oapi.dingtalk.com/topapi/processinstance/get?access_token={}&process_instance_id={}'.format(access_token, process_instance_id)
    resp = requests.post(url)
    return resp.text


def get_user_detail(access_token, userid):
    url = 'https://oapi.dingtalk.com/user/get?access_token={}&userid={}'.format(access_token, userid)
    resp = requests.get(url)
    return resp.text


def chinese_to_pinyin(sn):
    p = ''.join(lazy_pinyin(sn))
    return p


def get_user_info(username, user_attr="mobile", search_type="sn"):
    '''
    获取ldap用户手机号用于在钉钉通知消息中@人
    user_attr可以为ldap属性cn, ou, uid, sn, mail, mobile
    '''
    result = None
    user_result = ld.ldap_search_user(username, search_type)
    if user_result != []:
        result = user_result[0]["attributes"][user_attr][0]
    else:
        pass
    return result


def get_user_mobile(username, user_attr="mobile", search_type="sn"):
    '''
    获取ldap用户手机号用于在钉钉通知消息中@人
    user_attr可以为ldap属性cn, ou, uid, sn, mail, mobile
    '''
    result = None
    user_result = ld.ldap_search_user(username, search_type)
    if user_result != []:
        result = user_result[0]["attributes"]
    else:
        pass
    return result


def save_to_db(bill_type, sn, cn, mail, tel, group, submit_by, approval_by):
    register = models.Register()
    register.bill_type = bill_type
    register.sn = sn
    register.cn = cn
    register.mail = mail
    register.tel = tel
    register.group = group
    register.submit_by = submit_by
    register.approval_by = approval_by
    register.save()


def login(request):
    request.session.set_expiry(1800)
    if request.method == 'POST':
        name = request.POST.get('username')
        password = request.POST.get('password')
        error_msg_login = "账号或密码错误，请重新输入"
        user = auth.authenticate(username=name, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect("/result")
    return render(request, "login.html", locals())


@login_required
def delete_user(request):
    """
    get username from frontend, search user if exsit, and fill ther ohter attr, and save in sqlite, add key in sql type reg or quit, filter in result page
    """
    # auto logout
    request.session.set_expiry(1800)
    error_msg_delete_user = ""
    approval_person = [get_user_info(p, "cn") for p in ld.ldap_group_person()]
    lg.logger.info("approval_person is: %s" % approval_person)
    if request.method == 'GET':
        lg.logger.info("login success")
        return render(request, "delete_user.html", locals())
    elif request.method == 'POST':
        sn = chinese_to_pinyin(request.POST.get('sn'))
        phone = request.POST.get('tel')
        submit_by = request.user.last_name
        approval_by = request.POST.get('approval_by')
        bill_type = request.POST.get('submit_quit')
        lg.logger.info('sn inputted: %s', sn)

        # 查询ldap中是否存在要删除的用户, 不存在则不提交并提醒用户信息有误
        search_resp = get_user_info(sn, 'sn')
        lg.logger.info('sn in ldap: %s', search_resp)
        if search_resp is None:
            error_msg_delete_user = '用户%s不存在，请确保输入的“姓名全拼”无误，试试%s1?' % (sn, sn)
            messages.error(request, error_msg_delete_user)
            return render(request, "delete_user.html", locals())

        # 记录表单类型
        if bill_type == "提交删除账号申请":
            bill_type = "删除申请"
        else:
            bill_type = "未知"

        cn = get_user_info(sn, 'cn')
        mail = get_user_info(sn, 'mail')
        tel = get_user_info(sn, 'mobile')
        group = "未知"
        lg.logger.info(
                      '提交信息为：%s, %s, %s, %s, %s, %s, %s, %s', \
                      bill_type, sn, cn, mail, tel, group, submit_by, approval_by \
                      )
        lg.logger.info('is phone equal input phone? %s ?? %s', phone, tel)
        if tel != phone:
            error_msg_delete_user = '用户手机号错误或与输入的“姓名全拼”不属于同一个用户，试试修改为%s1?' % (sn)
            messages.error(request, error_msg_delete_user)
            return render(request, "delete_user.html", locals())

        save_to_db(bill_type, sn, cn, mail, tel, group, submit_by, approval_by)
        lg.logger.info('save info to db')

        # send dingding
        content = '你好，%s, 有新的离职表单待你审批, 请尽快审批哦\nhttp://vickey-wu.com:8002/approval/' % approval_by
        at_people = get_user_info(approval_by, "mobile", "cn")
        ding = dingding.Dingding(BOT_TOKEN, content, at_people)
        lg.logger.info("content: %s", content)
        lg.logger.info("would delete user: %s", sn)
        lg.logger.info("at_people: %s", at_people)
        ding.send_dingding()

        return redirect("/result")


def registration(request):
    resp = 'response content'
    return HttpResponse(resp)

    request.session.set_expiry(1800)
    error_msg_registration = ""
    approval_person = [get_user_info(p, "cn") for p in ld.ldap_group_person()]
    lg.logger.info("approval_person is: %s", approval_person)
    if request.method == 'GET':
        lg.logger.info("login success")
        return render(request, "registration.html", locals())
    elif request.method == 'POST':
        sn = request.POST.get('sn')
        cn = request.POST.get('cn')
        mail = request.POST.get('email')
        tel = request.POST.get('tel')
        group = request.POST.get('group')
        submit_by = request.POST.get('cn')
        approval_by = request.POST.get('approval_by')
        bill_type = request.POST.get('submit_regist')
        lg.logger.info('提交信息为：%s, %s, %s, %s, %s, %s, %s, %s', bill_type, cn, sn, mail, tel, group, submit_by, approval_by)

        # 如果注册信息项有为空的则不提交信息到数据库
        if not all((bill_type, sn, cn, mail, tel, group, submit_by, approval_by)):
            messages.error(request,"请将所有信息填写完整后再提交，否则提交信息不生效！")
            return render(request, "registration.html", locals())

        # 如果表单项不符合要求则提示修改
        if ck.check_isalnum(sn) == False \
            or ck.check_isdigit(tel) == False \
            or ck.check_isemail(mail) == False:
            messages.error(request,"请确保‘姓名全拼’不含有中文字符，‘手机号码’和‘个人邮箱’正确无误！")
            return render(request, "registration.html", locals())

        # 查询ldap中是否已存在将要注册的用户, 已存在则不提交并提醒用户修改注册姓名
        search_resp = get_user_info(sn, 'sn')
        lg.logger.info('sn: %s', sn)
        if search_resp is not None:
            error_msg_registration = '用户名%s已存在，请修改“姓名全拼”，如改为%s1' % (sn, sn)
            messages.error(request, error_msg_registration)
            return render(request, "registration.html", locals())

        if bill_type == "提交注册申请":
            bill_type = "注册申请"
        else:
            bill_type = "未知"

        # 有空增加修改表单功能
        # 写入数据库
        save_to_db(bill_type, sn, cn, mail, tel, group, submit_by, approval_by)
        
        # send dingding
        content = '你好，%s, 有新的入职表单待你审批, 请尽快审批哦\nhttp://vickey-wu.com:8002/approval/' % approval_by
        at_people = get_user_info(approval_by, "mobile", "cn")
        ding = dingding.Dingding(BOT_TOKEN, content, at_people)
        lg.logger.info("content: %s", content)
        lg.logger.info("cn: %s", cn)
        lg.logger.info("sn: %s", sn)
        lg.logger.info("at_people: %s", at_people)
        ding.send_dingding()

        # 表单提交后的提醒 
        messages.info(request,"您的申请已提交，请耐心等待审核通过，通过后您会收到短信及邮件，按邮件指引操作即可!")
        return render(request, "registration.html", locals())


@login_required
def permission_apply(request):
    resp = 'response content'
    request.session.set_expiry(1800)
    error_msg_registration = ""
    approval_person = [get_user_info(p, "cn") for p in ld.ldap_group_person()]
    lg.logger.info("approval_person is: %s", approval_person)
    if request.method == 'GET':
        lg.logger.info("login success")
        return render(request, "permission_apply.html", locals())
    elif request.method == 'POST':
        # 列表值为model字段
        model_column = ['group', 'leader', 'mail', 'permission_type', 'bill_type', 'approval_by']
        # 列表值为前台提交表单值
        post_keys = ['group', 'leader', 'email', 'permission_type', 'submit_permission', 'approval_by']
        post_values = [request.POST.get(v) for v in post_keys]
        # 生成用于提交到数据库的字典
        value_dict = {k: v for k, v in zip(model_column, post_values)}
        value_dict['submit_by'] = request.user.last_name
        lg.logger.info('提交信息为：%s', value_dict.items())
        lg.logger.info('提交信息为：%s', value_dict.values())

        # 如果表单信息项有为空的则不提交信息到数据库
        if not all(value_dict.values()):
            messages.error(request,"请将所有信息填写完整后再提交，否则提交信息不生效！")
            return render(request, "permission_apply.html", locals())

        # 如果表单项不符合要求则提示修改
        if ck.check_isemail(value_dict['mail']) == False :
            messages.error(request,"请确保‘邮箱’格式正确无误！")
            return render(request, "permission_apply.html", locals())

        if value_dict['bill_type'] == "提交权限申请":
            value_dict['bill_type'] = "权限申请"
        else:
            value_dict['bill_type'] = "未知"

        # 写入数据库
        permission_application = models.PermissionApply()
        permission_application.bill_type = value_dict['bill_type']
        permission_application.group = value_dict['group']
        permission_application.leader = value_dict['leader']
        permission_application.mail = value_dict['mail']
        permission_application.permission_type = value_dict['permission_type']
        permission_application.approval_by = value_dict['approval_by']
        permission_application.submit_by = value_dict['submit_by']
        permission_application.save()
        
        # 表单提交后的提醒 
        messages.info(request,"您的申请已提交，请耐心等待审核通过，通过后将会将通知发送到您刚才填写的验证邮箱! 请注意查收!")

        # send dingding
        content = '你好，%s, 有新的权限申请单待你审批, 请尽快审批哦\nhttp://vickey-wu.com:8002/approval/' % value_dict['approval_by']
        at_people = get_user_info(value_dict['approval_by'], "mobile", "cn")
        ding = dingding.Dingding(BOT_TOKEN, content, at_people)
        lg.logger.info("content: %s", content)
        ding.send_dingding()
        return render(request, "permission_apply.html", locals())


def email_apply(request):
    resp = 'response content'
    request.session.set_expiry(1800)
    error_msg_registration = ""
    approval_person = [get_user_info(p, "cn") for p in ld.ldap_group_person()]
    lg.logger.info("approval_person is: %s", approval_person)
    if request.method == 'GET':
        lg.logger.info("login success")
        return render(request, "email_apply.html", locals())
    elif request.method == 'POST':
        # 列表值为model字段
        model_column = ['cn', 'submit_by', 'tel', 'group', 'leader', 'enterprise_mail', 'mail', 'bill_type', 'approval_by']
        # 列表值为前台提交表单值
        post_keys = ['cn', 'cn', 'tel', 'group', 'leader', 'enterprise_mail', 'email', 'submit_email', 'approval_by']
        post_values = [request.POST.get(v) for v in post_keys]
        # 生成用于提交到数据库的字典
        value_dict = {k: v for k, v in zip(model_column, post_values)}
        lg.logger.info('提交信息为：%s', post_values)

        # 如果表单信息项有为空的则不提交信息到数据库
        if not all(post_values):
            messages.error(request,"请将所有信息填写完整后再提交，否则提交信息不生效！")
            return render(request, "email_apply.html", locals())

        # 如果表单项不符合要求则提示修改
        if ck.check_isdigit(value_dict['tel']) == False \
            or ck.check_isemail(value_dict['mail']) == False \
            or ck.check_isemail(value_dict['enterprise_mail']) == False:
            messages.error(request,"请确保‘手机号码’和‘邮箱’格式正确无误！")
            return render(request, "email_apply.html", locals())

        if value_dict['bill_type'] == "提交邮箱申请":
            value_dict['bill_type'] = "邮箱申请"
        else:
            value_dict['bill_type'] = "未知"

        # 写入数据库
        email_application = models.EmailApply()
        email_application.bill_type = value_dict['bill_type']
        email_application.cn = value_dict['cn']
        email_application.tel = value_dict['tel']
        email_application.group = value_dict['group']
        email_application.leader = value_dict['leader']
        email_application.enterprise_mail = value_dict['enterprise_mail']
        email_application.mail = value_dict['mail']
        email_application.submit_by = value_dict['submit_by']
        email_application.approval_by = value_dict['approval_by']
        email_application.save()

        # 表单提交后的提醒 
        messages.info(request,"您的申请已提交，请耐心等待审核，审核通过后将会将通知发送到您的私人邮箱, 之后您就可以使用申请的公司邮箱啦!")
        
        # send dingding
        content = '你好，%s, 有新的邮箱申请单待你审批, 请尽快审批哦\nhttp://vickey-wu.com:8002/approval/' % value_dict['approval_by']
        at_people = get_user_info(value_dict['approval_by'], "mobile", "cn")
        ding = dingding.Dingding(BOT_TOKEN, content, at_people)
        lg.logger.info("content: %s", content)
        ding.send_dingding()
        return render(request, "email_apply.html", locals())


@login_required
def result(request):
    # auto logout
    request.session.set_expiry(1800)
    user_name = request.user.last_name
    bill_type = request.GET.get('bill_type')
    result = []
    if bill_type == 'register':
        thead = ['表单ID', '表单类型', '姓名全拼', '中文姓名', '公司邮箱', '手机号码', '所属部门', '审批状态', '审批人员']
        result = models.Register.objects.filter(submit_by=user_name)
    elif bill_type == 'email':
        thead = ['表单ID', '表单类型', '中文姓名', '手机号码', '所属部门', '部门主管', '公司邮箱',  '私人邮箱', '审批状态', '审批人员']
        result = models.EmailApply.objects.filter(submit_by=user_name)
    elif bill_type == 'permission':
        thead = ['表单ID', '表单类型', '所属部门', '部门主管', '验证邮箱', '权限类别', '审批状态', '审批人员']
        result = models.PermissionApply.objects.filter(submit_by=user_name)
    if len(result) == 0:
        return render(request, "result.html", {'result_msg': '没有您提交的申请单'})
    register = models.Register()
    return render(request, "result.html", locals())


def send_note(tel, mail, random_password):
    if sms.send_sms(tel, mail) == 'OK':
        lg.logger.info('短信通知发送成功！')
        email = em.Mail('test@vickey-wu.com', 'mypassword')
        mail_content = 'test content' % (random_password, random_password)
        email.send_email(mail, mail_content)
        lg.logger.info(mail_content)


@login_required
def approval(request):
    # auto logout
    request.session.set_expiry(1800)
    # 从数据库获取数据来填充网页
    if request.method == 'GET':
        # 如果是get请求，则筛选出状态为未通过的审批单给审批人审批
        last_name = request.user.last_name
        user_name = request.user.username
        bill_type = request.GET.get('bill_type')
        result = []
        if bill_type == 'register':
            thead = ['表单ID', '表单类型', '姓名全拼', '中文姓名', '公司邮箱', '手机号码', '所属部门', '提交人员', '审批状态', '操作']
            result = models.Register.objects.filter(approval_by=last_name, approval_status='未通过')
        elif bill_type == 'email':
            thead = ['表单ID', '表单类型', '中文姓名', '手机号码', '所属部门', '部门主管', '公司邮箱', '私人邮箱', '提交人员', '审批状态', '操作']
            result = models.EmailApply.objects.filter(approval_by=last_name, approval_status='未通过')
        elif bill_type == 'permission':
            thead = ['表单ID', '表单类型',  '权限类别', '所属部门', '验证邮箱', '提交人员', '审批状态', '操作']
            result = models.PermissionApply.objects.filter(approval_by=last_name, approval_status='未通过')
        if len(result) == 0:
            return render(request, "approval.html", {'approval_msg': '没有待您审批的审批单'})
        return render(request, "approval.html", locals())

    elif request.method == 'POST':
        last_name = request.user.last_name
        bill_id = request.GET.get('bill_id')
        bill_type = request.GET.get('bill_type')
        aps = request.POST.get('approval_status')
        email = em.Mail('test@vickey-wu.com', 'mypassword')

        # 调用已经写好的ldap3_add_user.py将用户信息写入ldap数据库
        if aps == '通过':
            # 更新选中的表单的审批状态和是否写入ldap数据库状态，1为已写入
            if bill_type == "register":
                try:
                    # .values('key') 返回以key为键，以Register的值为值的字典，exam: [{'id': 1, 'name': 'Beatles Blog'}]
                    result = models.Register.objects.filter(id=bill_id).values('cn', 'sn', 'mail', 'tel', 'group')[0]
                    # example: cn, sn, mail, tel, group = 'vickey-wu', '吴悟无', '8888888888@qq.com', '12346578910', '研发中心'
                    cn, sn, mail, tel, group = result['cn'], result['sn'], result['mail'], result['tel'], result['group']
                    passwd = ld.random_passwd()
                    lg.logger.info([cn, sn, mail, tel, group, passwd])
                    add_status = ld.ldap_add_user(cn, sn, mail, tel, group, passwd)
                    lg.logger.info("raw passwd in view is：%s", passwd)
                    lg.logger.info("表单审批状态为：%s", add_status)
                    if add_status == 'success':
                        #添加用户到ldap成功后修改sqlite审批状态
                        models.Register.objects.filter(id=bill_id).update(approval_status=aps)
                        lg.logger.info('表单%s已写入ldap数据库' % bill_id)
                        # 审批通过后发送短信通知用户，并发送初始账号信息到注册用户邮箱
                        send_note(tel, mail, passwd)

                #添加用户到ldap返回非success则表明用户已存在
                except Exception as e:
                    lg.logger.info('写入ldap数据库报错: %s', e)
            elif bill_type == "delete":
                try:
                    result = models.Register.objects.filter(id=bill_id).values('sn')[0]
                    sn = result['sn']
                    delete_status = ld.ldap_delete_user(sn)
                    if delete_status and delete_status == 'success':
                        #添加用户到ldap成功后修改sqlite审批状态
                        models.Register.objects.filter(id=bill_id).update(approval_status=aps)
                        lg.logger.info('%s表单%s已写入ldap数据库,状态: %s' % (bill_type, bill_id, delete_status))
                    else:
                        lg.logger.info("删除表单用户已不存在ldap数据库")

                    ## 删除用户vickey-wu.com的邮箱
                    ex =  exmail.Exmail()
                    exsited_email =  ex.get_email(sn + '@vickey-wu.com')
                    if exsited_email:
                        delete_status = ex.delete_email(sn + '@vickey-wu.com')
                        if delete_status:
                            lg.logger.info("已删除用户%s的vickey-wu.com邮箱" % sn)
                    else:
                        lg.logger.info("用户%s没有vickey-wu.com的邮箱" % sn)
                except Exception as e:
                    lg.logger.info("删除表单用户已不存在ldap数据库: %s", e)
            elif bill_type == 'email':
                # 更新审批状态
                models.EmailApply.objects.filter(id=bill_id).update(approval_status=aps)
                lg.logger.info('信息系统%s表单%s审批状态已修改为"通过"' % (bill_type, bill_id))
                # 发送邮件通知
                result = models.EmailApply.objects.filter(id=bill_id).values('enterprise_mail', 'mail')[0]
                enterprise_mail, mail = result['enterprise_mail'], result['mail']
                mail_content = '您申请的企业邮箱%s已审批通过, 使用微信扫码即可登录, 如有问题可联系审批人员解决' % enterprise_mail
                email.send_email(mail, mail_content)
                lg.logger.info(mail_content)
            elif bill_type == 'permission':
                # 更新审批状态
                models.PermissionApply.objects.filter(id=bill_id).update(approval_status=aps)
                lg.logger.info('信息系统%s表单%s审批状态已修改为"通过"' % (bill_type, bill_id))
                # 发送邮件通知
                result = models.PermissionApply.objects.filter(id=bill_id).values('permission_type', 'mail')[0]
                permission_type, mail = result['permission_type'], result['mail']
                mail_content = '您申请的权限"%s"已审批通过, 现在就刷新需要权限的的后台或重新登录试试吧, 如有问题可联系审批人员解决' % permission_type
                email.send_email(mail, mail_content)
                lg.logger.info(mail_content)
            else:
                lg.logger.info('表单类型未知, 未提交任何操作')
                pass
        else:
            lg.logger.info('忽略提交状态未通过和已写入ldap数据库的表单%s' % bill_id)
            pass

        # 审批提交后停留在审批页面
        html = 'approval/?bill_type=%s' % bill_type
        return HttpResponseRedirect(html)
