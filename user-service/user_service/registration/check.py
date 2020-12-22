#!/usr/bin/python
# -*- coding: utf-8 -*-


from django.core.validators import validate_email
from registration import log


class Check():
    """
    check whether parameters valid
    """

    def __init__(self):
        self.lg = log.Logger("./log/check_log.log",level="info")

    def check_isalnum(self, keyword):
        """
        check keyword passed whether is alpha or num
        """
        if keyword.isalnum():
            for k in keyword:
                # chinese characters range in unicode
                if '\u4e00' <= k <= '\u9fa5':
                    self.lg.logger.error("keyword '%s' required alpha or number", keyword)
                    return False
            else:
                self.lg.logger.info("keyword is: %s", keyword)
                return keyword
        else:
            self.lg.logger.error("keyword '%s' required alpha or number", keyword)
            return False

    def check_isdigit(self, keyword):
        """
        check keyword passed whether is num
        """
        if len(keyword) == 11 and keyword.isdigit():
            self.lg.logger.info("keyword is: %s", keyword)
            return keyword
        else:
            self.lg.logger.error("telephone required 11 number")
            return False

    def check_isemail(self, keyword):
        """
        check keyword passed whether is legal email
        """
        try:
            validate_email(keyword)
            self.lg.logger.info("keyword is: %s", keyword)
            if ".com" in keyword:
                return keyword
            else:
                return False
        except Exception as e:
            self.lg.logger.error("input correct email")
            return False
