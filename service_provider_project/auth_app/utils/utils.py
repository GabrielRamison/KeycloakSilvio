# service_provider/auth_app/utils.py
import secrets
import hashlib
import base64
from django.conf import settings

def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip(b'=').decode('ascii')

def generate_pkce():
    verifier_bytes = secrets.token_bytes(32)
    verifier = base64url_encode(verifier_bytes)
    
    challenge_bytes = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64url_encode(challenge_bytes)
    
    return verifier, challenge

def store_pkce(state, data):
    if not hasattr(settings, 'PKCE_STORE'):
        settings.PKCE_STORE = {}
    settings.PKCE_STORE[state] = data
    print('Stored PKCE data for state:', state)

def get_pkce(state):
    if not hasattr(settings, 'PKCE_STORE'):
        return None
    data = settings.PKCE_STORE.get(state)
    print('Retrieved PKCE data for state:', state, bool(data))
    return data

def clear_pkce(state):
    if hasattr(settings, 'PKCE_STORE'):
        settings.PKCE_STORE.pop(state, None)
        print('Cleared PKCE data for state:', state)