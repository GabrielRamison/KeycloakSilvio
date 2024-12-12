# service_provider/keycloak_client/oauth2_client.py
import os
import json
import secrets
import hashlib
import base64
import requests
from django.conf import settings

class OAuth2Client:
    def get_openid_config(self):
        raise NotImplementedError()
    
    def get_access_token(self, code):
        raise NotImplementedError()
    
    def get_user_info(self, access_token):
        raise NotImplementedError()
    
    def get_authenticator_url(self):
        raise NotImplementedError()
    
    def get_logout_url(self, redirect_uri):
        raise NotImplementedError()

class KeycloakOAuth2Client(OAuth2Client):
    def __init__(self):
        self.base_url = f"{settings.INTERNAL_KEYCLOAK_URL}/auth"
        self.realm = settings.KEYCLOAK_REALM
        self.client_id = settings.KEYCLOAK_CLIENT_ID
        self.client_secret = settings.KEYCLOAK_CLIENT_SECRET
        self.redirect_uri = f"{settings.APP_URL}/callback"

        # Endpoints
        self.token_endpoint = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        self.userinfo_endpoint = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/userinfo"
        
        print(f'KeycloakOAuth2Client initialized with: base_url={self.base_url}, realm={self.realm}')

    def get_openid_config(self):
        try:
            url = f"{self.base_url}/realms/{self.realm}/.well-known/openid-configuration"
            print(f"Requesting OpenID config from: {url}")
            response = requests.get(url)
            return response.json()
        except Exception as error:
            print(f"Error fetching OpenID config: {error}")
            raise

    def generate_pkce(self):
        verifier_bytes = secrets.token_bytes(32)
        verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b'=').decode('ascii')
        challenge_bytes = hashlib.sha256(verifier.encode('ascii')).digest()
        challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b'=').decode('ascii')
        return verifier, challenge

    def get_access_token(self, code, state):
        try:
            if state not in getattr(settings, 'PKCE_STORE', {}):
                raise ValueError('Invalid state parameter')

            verifier = settings.PKCE_STORE[state]
            del settings.PKCE_STORE[state]

            data = {
                'grant_type': 'authorization_code',
                'code': code,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'redirect_uri': self.redirect_uri,
                'code_verifier': verifier
            }
            
            response = requests.post(
                self.token_endpoint,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            return response.json()
        except Exception as error:
            print(f"Token exchange error: {error}")
            raise

    def get_user_info(self, access_token):
        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers={'Authorization': f'Bearer {access_token}'}
            )
            return response.json()
        except Exception as error:
            print(f"UserInfo error: {error}")
            raise

    def get_authenticator_url(self):
        try:
            config = self.get_openid_config()
            auth_url = config['authorization_endpoint'].replace(
                self.base_url,
                'http://localhost:8080/auth'
            )

            verifier, challenge = self.generate_pkce()
            state = secrets.token_hex(16)
            
            if not hasattr(settings, 'PKCE_STORE'):
                settings.PKCE_STORE = {}
            settings.PKCE_STORE[state] = verifier

            params = {
                'client_id': self.client_id,
                'redirect_uri': self.redirect_uri,
                'response_type': 'code',
                'scope': 'openid email profile',
                'state': state,
                'code_challenge': challenge,
                'code_challenge_method': 'S256'
            }

            from urllib.parse import urlencode
            final_url = f"{auth_url}?{urlencode(params)}"
            print(f'Generated auth URL: {final_url}')
            
            return final_url
        except Exception as error:
            print(f"Error getting authenticator URL: {error}")
            raise

    def get_logout_url(self, redirect_uri=None):
        try:
            redirect_uri = redirect_uri or self.redirect_uri
            config = self.get_openid_config()
            end_session_endpoint = config['end_session_endpoint'].replace(
                self.base_url,
                'http://localhost:8080/auth'
            )
            
            from urllib.parse import urlencode
            params = {'redirect_uri': redirect_uri}
            return f"{end_session_endpoint}?{urlencode(params)}"
        except Exception as error:
            print(f"Error getting logout URL: {error}")
            raise