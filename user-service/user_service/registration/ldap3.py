#!/usr/bin/python
# -*- coding: utf-8 -*-


from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_DELETE, MODIFY_ADD, ALL_ATTRIBUTES
from django.conf import settings as ldap_setting
from registration import check
from registration  import log

import passlib.hash
import random
import string
import re
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "user_registration.settings")


class Ldap3(object):
    """process ldap login, search, add function"""
    def __init__(self):
        self.lg = log.Logger("./log/ldap3_log.log",level="info")
        self.check = check.Check()
        self.search_base_users = "ou=users,dc=vickey-wu,dc=com"
        self.search_base_groups = "ou=groups,dc=vickey-wu,dc=com"
        self.ldap_approval_group = "administrators"
        self.ldap_tech_center_authorities = ["users", "gitlab-users", "backend-users"]
        self.ldap_other_center_authorities = ["users"]

    def ldap_login(self):
        ldap_server = Server(ldap_setting.AUTH_LDAP_SERVER_URI, get_info=ALL)
        ldap_con = Connection(
                             ldap_server, 
                             user=ldap_setting.AUTH_LDAP_BIND_DN, 
                             password=ldap_setting.AUTH_LDAP_BIND_PASSWORD, 
                             auto_bind=True
                             )
        return ldap_con

    def ldap_search_user(self, search_key, search_type="sn"):
        if search_type == "sn":
            search_filter = "(&(objectClass=inetOrgPerson)(sn=" + search_key + "))"
        elif search_type == "cn":
            search_filter = "(&(objectClass=inetOrgPerson)(cn=" + search_key + "))"
        else:
            self.lg.logger.error("search_type '%s' is invalid, please input 'sn' or 'cn'", search_type)
            return []
        search_base = self.search_base_users
        con = self.ldap_login()
        attributes=ALL_ATTRIBUTES
        con.search(search_base, search_filter, attributes=attributes)
        #self.lg.logger.info("search result: %s", con.response)
        return con.response

    def ldap_search_group(self, search_key):
        # e.g: (&(objectClass=inetOrgPerson)(sn=xxxxxxx))
        search_filter = "(&(objectClass=groupOfUniqueNames)(cn=" + search_key + "))"
        search_base = self.search_base_groups
        con = self.ldap_login()
        self.lg.logger.info("search_key is: %s", search_key)
        self.lg.logger.info("search_base is: %s", search_base)
        self.lg.logger.info("search_filter is: %s", search_filter)
        attributes=ALL_ATTRIBUTES
        con.search(search_base, search_filter, attributes=attributes)
        #self.lg.logger.info("search result: %s", con.response)
        return con.response

    def get_member_uid(self, dn):
        uid = re.match("uid=(.*?),.*?", dn)
        self.lg.logger.info("match uid: %s", uid.group(1))
        return uid.group(1)

    def ldap_group_person(self):
        group_info = self.ldap_search_group(self.ldap_approval_group)
        members = group_info[0]["attributes"]["uniqueMember"]
        person_list = [self.get_member_uid(p) for p in members]
        self.lg.logger.info("person list: %s", person_list)
        return person_list

    def ldap_group_authority_mapper(self, group):
        self.lg.logger.info("group mapper type is: %s, group mapper is: %s", type(group), group)
        if group == "研发中心":
            group = self.ldap_tech_center_authorities
        elif group == "大数据中心":
            group = self.ldap_data_center_authorities
        else:
            group = self.ldap_other_center_authorities
        self.lg.logger.info("group list: %s", group)
        return group

    def ldap_add_authority(self, sn, group, ldap_group=None, additiaonal=False):
        """
        reference: https://ldap3.readthedocs.io/modify.html
        ldap3 add authority for new user
        """
        con = self.ldap_login()
        # changes format: changes_dict(attr_key:value_list(tuple(MODIFY_ADD,replace_list())))
        uniquemember = "uid=" + sn + ",ou=users,dc=vickey-wu,dc=com"
        uniqueMember = [(MODIFY_ADD, [uniquemember])]
        changes = {
                     "uniqueMember": uniqueMember,
                     }
        # if ldap_group is not None and additiaonal is True then combine two group 
        if not isinstance(group, list):
            group = self.ldap_group_authority_mapper(group)
        ## 旧的注册和申请权限在一起，所以将默认权限和申请的权限加在一起additiaonal设为True，
        ## 新的逻辑要分开，所以additiaonal设为False
        if ldap_group is not None:
            if additiaonal is True:
                self.lg.logger.info("additiaonal group is: %s", additiaonal)
                group.append(ldap_group)
            if additiaonal is False:
                self.lg.logger.info("additiaonal group is: %s", additiaonal)
                group = [ldap_group]
        self.lg.logger.info("ldap group is: %s", group)
        if self.check.check_isalnum(sn) and group is not None:
            # add more authorities for one user
            for group_cn in group:
                if group_cn != "":
                    # e.g: dn = "cn=administrators,ou=groups,dc=vickey-wu,dc=com"
                    dn = "cn=" + group_cn +",ou=groups,dc=vickey-wu,dc=com"
                    self.lg.logger.info("group_cn is: %s", group_cn)
                    con.modify(dn, changes)
                    # is_add: success: "success", exists: "attributeOrValueExists"
                    #is_add = con.result['description']
                    self.lg.logger.info("ldap authorities add result: %s", con.result)
                else:
                    self.lg.logger.info("error: group list include null ''")
        else:
            self.lg.logger.info("input correct uid or select group")
        # unbind ldap server
        con.unbind()

    @staticmethod
    def random_passwd():
        raw_str=string.ascii_letters + string.digits
        random_str = random.sample(raw_str, 16)
        random_passwd = ''.join(random_str)
        return random_passwd

    def sha_passwd(self, random_passwd):
        self.lg.logger.info('raw passwd in sha is: %s', random_passwd)
        sha_passwd = passlib.hash.ldap_sha1.encrypt(random_passwd)
        self.lg.logger.info('SHA passwd is: %s', sha_passwd)
        return sha_passwd

    def ldap_add_user(self, cn, sn, mail, tel, group, passwd):
        """
        reference: https://ldap3.readthedocs.io/add.html?highlight=add%20group
        ldap3 add user
        """
        self.lg.logger.info('raw passwd in add_user is: %s', passwd)
        con = self.ldap_login()
        group = self.ldap_group_authority_mapper(group)
        uid = sn
        ou = "users"
        dn = "uid=" + uid + ",ou=" + ou + ",dc=vickey-wu,dc=com"
        # default ldap add operation parameters
        objectclass = ["inetOrgPerson", "top"]
        # default ldap user SHA password: test
        #default_passwd = "{SHA}xxxxxxxxxx="
        default_passwd = self.sha_passwd(passwd)
        attributes = {
                     "objectClass":  objectclass,
                     "cn": cn,
                     "mail": mail,
                     "mobile": tel,
                     "ou": ou,
                     "sn": sn,
                     "uid": uid,
                     "userPassword": default_passwd
                     }
        if self.check.check_isalnum(sn) and self.check.check_isdigit(tel) and self.check.check_isemail(mail):
            #the same as follow: con.add(dn, object_class=objectclass, attributes=attributes)
            con.add(dn, attributes=attributes)
            # is_add: success: "success", exists: "entryAlreadyExists"
            is_add = con.result['description']
            self.lg.logger.info("registration result: user '%s' registration is %s", uid, con.result)
            # if user is new registration it would return success then add user default authorities
            if is_add == "success":
                self.ldap_add_authority(uid, group)
                self.lg.logger.info("user add result: %s", is_add)
            return is_add
        else:
            self.lg.logger.error("input correct format parameters")
        # unbind ldap server
        con.unbind()

    def ldap_delete_user(self, sn):
        """
        reference: https://ldap3.readthedocs.io/modify.html?highlight=delete%20uid#the-modify-operation
        ldap3 delete user, user's authorities would be delete too
        """
        con = self.ldap_login()
        dn = "uid=" + sn + ",ou=users,dc=vickey-wu,dc=com"
        # conn.modify('uid=colttt,cn=users,dc=example,dc=de',{'telephoneNumber': [(ldap3.MODIFY_REPLACE, [])], 'roomNumber': [(ldap3.MODIFY_REPLACE, [])]})
        #dn = "uid=caixingfang,ou=users,dc=vickey-wu,dc=com"
        self.lg.logger.info("user dn: %s", dn)
        #con.delete('cn=user1,ou=users,o=company')
        con.delete(dn)
        is_delete = con.result['description']
        if is_delete == "success":
            self.lg.logger.info("user delete result: %s", is_delete)
            return is_delete
        else:
            self.lg.logger.error("user not existed or deleted")
        
        # unbind ldap server
        con.unbind()


#ld = Ldap3()
#cn, sn, mail, tel, group = '吴悟无', 'vickey-wu', '888888888@qq.com', '1888888888888', '研发中心'
#ld.ldap_add_user(cn, sn, mail, tel, group)
#ld.ldap_search_user("vickey-wu", 'cn')
#ld.ldap_delete_user("vickey-wu")
#ld.ldap_group_person()
