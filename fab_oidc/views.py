import os
from flask import redirect, request, current_app
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from flask_admin import expose
from urllib.parse import quote, urlparse


# Set the OIDC field that should be used as a username
USERNAME_OIDC_FIELD = os.getenv('USERNAME_OIDC_FIELD', default='sub')
FIRST_NAME_OIDC_FIELD = os.getenv('FIRST_NAME_OIDC_FIELD',
                                  default='nickname')
LAST_NAME_OIDC_FIELD = os.getenv('LAST_NAME_OIDC_FIELD',
                                 default='name')

OVERWRITE_REDIRECT_URI = 

def get_airflow_roles(k_roles):
  if 'admin' in k_roles:
    return 'Admin'
  if 'op' in k_roles:
    return 'Op'
  else:
    return 'User'

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):

        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))           
            if user is None:
                tinfo =oidc.user_getinfo([USERNAME_OIDC_FIELD, 'email', LAST_NAME_OIDC_FIELD, FIRST_NAME_OIDC_FIELD, 'nickname', 'roles'])
                user = sm.add_user(
                    username=tinfo.get(USERNAME_OIDC_FIELD),
                    first_name=tinfo.get(FIRST_NAME_OIDC_FIELD),
                    last_name=tinfo.get(LAST_NAME_OIDC_FIELD),
                    email=tinfo.get('email'),
                    role=sm.find_role(get_airflow_roles(tinfo.get('roles')))
                )

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):

        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        
        redirect_uri = current_app.config['OVERWRITE_REDIRECT_URI']
        if redirect_uri:
            parsed_uri = urlparse(redirect_uri)
            redirect_url = parsed_uri.scheme + "://" + parsed_uri.hostname + self.appbuilder.get_url_for_login
        else:
            redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login

        logout_uri = oidc.client_secrets.get(
            'issuer') + '/protocol/openid-connect/logout?redirect_uri='
        if 'OIDC_LOGOUT_URI' in self.appbuilder.app.config:
            logout_uri = self.appbuilder.app.config['OIDC_LOGOUT_URI']

        return redirect(logout_uri + quote(redirect_url))
