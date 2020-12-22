import json
import requests
from registration  import log


lg = log.Logger('./log/keycloak_log.log',level='debug')


def get_keycloak_token(realm='test-realm'):
    data = {
           'client_id': 'admin-cli',
           'grant_type': 'password',
           'username': 'xxxxxxx',
           'password': 'xxxxxxxxxx',
           }
    server_url = 'https://auth.vickey-wu.com/auth'

    token_url = '{}/realms/{}/protocol/openid-connect/token'.format(server_url, realm)
    req = requests.post(token_url, data=data)
    req_token = json.loads(req.text)['access_token']

    lg.logger.info('keycloak access token: {}'.format(req_token))
    return req_token


def add_realm_role_to_user(username, realm, role_name):
    #realm = 'test-realm'
    server_url = 'https://auth.vickey-wu.com/auth'
    req_token = get_keycloak_token(realm)

    headers = {'X-Requested-With': 'XMLHttpRequest', 'Authorization': 'bearer %s' % req_token}
    uid_url = '{}/admin/realms/{}/users?briefRepresentation=true&first=0&max=20&search={}'.format(server_url, realm, username)
    req = requests.get(uid_url, headers=headers)
    uid = json.loads(req.text)[0]['id']
    lg.logger.info('keycloak uid: {}'.format(uid))

    all_roles_url = '{}/admin/realms/{}/roles'.format(server_url, realm)
    req = requests.get(all_roles_url, headers=headers)
    all_roles = json.loads(req.text)
    lg.logger.info('keycloak all roles: {}'.format(all_roles))

    add_role_url = '{}/admin/realms/{}/users/{}/role-mappings/realm'.format(server_url, realm, uid)
    add_role_data = []
    for r in all_roles:
        if r['name'] == role_name:
            add_role_data.append(r)
            break
    add_role_data = json.dumps(add_role_data)
    # Content-Type must be json
    role_headers = {'Content-Type':'application/json', 'Authorization': 'Bearer %s' % req_token}
    lg.logger.info('keycloak add_role_data: {}'.format(add_role_data))
    req = requests.post(add_role_url, data=add_role_data, headers=role_headers)
    status = req.status_code
    lg.logger.info('keycloak add role status: {}'.format(status))
    if status != 204:
        return False
    else:
        return True


#print(add_realm_role_to_user('name', 'test'))
