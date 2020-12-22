# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


class Register(models.Model):
     cn = models.CharField(max_length=120)
     sn = models.CharField(max_length=120)
     mail = models.CharField(max_length=120)
     tel = models.CharField(max_length=120)
     group = models.CharField(max_length=120)
     submit_by = models.CharField(max_length=120, default='未知')
     bill_type = models.CharField(max_length=120, default='未知')
     approval_by = models.CharField(max_length=120, default='未知')
     approval_status = models.CharField(max_length=120, default='未通过')


class EmailApply(models.Model):
     cn = models.CharField(max_length=120)
     tel = models.CharField(max_length=120)
     group = models.CharField(max_length=120)
     leader = models.CharField(max_length=120)
     enterprise_mail = models.CharField(max_length=120)
     mail = models.CharField(max_length=120)
     submit_by = models.CharField(max_length=120, default='未知')
     bill_type = models.CharField(max_length=120, default='未知')
     approval_by = models.CharField(max_length=120, default='未知')
     approval_status = models.CharField(max_length=120, default='未通过')


class PermissionApply(models.Model):
     group = models.CharField(max_length=120)
     leader = models.CharField(max_length=120)
     mail = models.CharField(max_length=120)
     permission_type = models.CharField(max_length=120)
     submit_by = models.CharField(max_length=120, default='未知')
     bill_type = models.CharField(max_length=120, default='未知')
     approval_by = models.CharField(max_length=120, default='未知')
     approval_status = models.CharField(max_length=120, default='未通过')
