FROM vickeywu/django-python3-onbuild

EXPOSE 8000

RUN apt-get update -y \
 && apt-get install apt-utils -y \
 && apt-get install python-dev -y \
 && apt-get install libldap2-dev -y \
 && apt-get install libsasl2-dev -y \
 && apt-get install libevent-dev -y \
 && apt-get install build-essential -y \
 && apt-get install curl -y \
 && apt-get install vim -y

RUN apt-get install python-pip -y \
 && pip install requests \
 && pip install --upgrade ldap3 \
 && pip install pypinyin \
 && pip install qcloudsms_py \
 && pip install passlib \
 && pip install typing

RUN pip install django-auth-ldap \
 && pip install python-keycloak

WORKDIR /home/user-registration/

CMD python manage.py runserver 0:8000
