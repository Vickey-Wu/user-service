import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
from registration  import log


class Mail(object):
    def __init__(self, server_account, server_passwd, server_addr='smtp.qiye.aliyun.com', server_port=465):
        self.lg = log.Logger("./log/ldap3_log.log",level="info")
        self.server_account = server_account
        self.server_passwd = server_passwd
        self.server_addr = server_addr
        self.server_port = server_port

    def send_email(self, receiver_email, content):
        msg = MIMEText(content, "plain", 'utf-8')
        msg['From'] = formataddr(["vickey-wu.com tech", self.server_account])
        msg['To'] = formataddr(["receiver", receiver_email])
        msg['Subject'] = "registration note"

        try:
            server = smtplib.SMTP_SSL("smtp.qiye.aliyun.com", 465)
            server.login(self.server_account, self.server_passwd)
            server.sendmail(self.server_account, receiver_email, msg.as_string())
            server.quit()
        except Exception as e:
            self.lg.logger.info("send email failed: %s", e)

#m = Mail('xxxxx@vickey-wu.com', 'xxxxxxxxxxx')
#m.send_email('xxxxxxxxx@vickey-wu.com', 'test init')

