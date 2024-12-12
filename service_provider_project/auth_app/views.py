# service_provider/auth_app/views.py
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from .clients.oauth2_client import KeycloakOAuth2Client
import secrets

class AuthController:
    @staticmethod
    def home(request):
        access_token = request.COOKIES.get('accessToken')
        
        if access_token:
            try:
                client = KeycloakOAuth2Client()
                user_info = client.get_user_info(access_token)
                return HttpResponse(f"""
                    <h1>Welcome {user_info.get('name', 'User')}</h1>
                    <div>
                        <h2>User Profile</h2>
                        <p>Email: {user_info.get('email', 'Not available')}</p>
                        <p>ID: {user_info.get('sub', '')}</p>
                        <hr/>
                        <a href="/logout">Logout</a>
                    </div>
                """)
            except Exception:
                response = redirect('/login')
                response.delete_cookie('accessToken')
                return response
        else:
            return HttpResponse("""
                <h1>Welcome to Service Provider</h1>
                <div>
                    <a href="/login">Login</a>
                    <span> | </span>
                    <a href="/register">Register</a>
                </div>
            """)

    @staticmethod
    def register(request):
        client = KeycloakOAuth2Client()
        verifier, challenge = client.generate_pkce()
        state = secrets.token_hex(16)
        
        if not hasattr(settings, 'PKCE_STORE'):
            settings.PKCE_STORE = {}
        settings.PKCE_STORE[state] = {'verifier': verifier, 'challenge': challenge}

        auth_url = client.get_authenticator_url()
        return redirect(auth_url)

    @staticmethod
    def login(request):
        client = KeycloakOAuth2Client()
        auth_url = client.get_authenticator_url()
        return redirect(auth_url)

    @staticmethod
    def callback(request):
        code = request.GET.get('code')
        state = request.GET.get('state')
        
        if 'error' in request.GET:
            print(f"Auth error: {request.GET.get('error')}, {request.GET.get('error_description')}")
            return redirect('/login')
            
        if state not in getattr(settings, 'PKCE_STORE', {}):
            return HttpResponse('Invalid state parameter', status=400)
            
        try:
            client = KeycloakOAuth2Client()
            token_data = client.get_access_token(code, state)
            
            response = redirect('/')
            response.set_cookie(
                'accessToken',
                token_data['access_token'],
                max_age=3600,
                httponly=True,
                secure=settings.DEBUG is False
            )
            
            del settings.PKCE_STORE[state]
            return response
        except Exception as error:
            print(f'Token exchange error: {error}')
            return redirect('/login')

    @staticmethod
    def logout(request):
        client = KeycloakOAuth2Client()
        logout_url = client.get_logout_url()
        
        response = redirect(logout_url)
        response.delete_cookie('accessToken')
        return response