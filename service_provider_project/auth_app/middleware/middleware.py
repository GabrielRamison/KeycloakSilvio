# service_provider/auth_app/middleware.py
import jwt
from django.conf import settings

class TokenDebugMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.COOKIES.get('accessToken')
        if token:
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                print('Token debug:', {
                    'iss': decoded.get('iss'),
                    'sub': decoded.get('sub'),
                    'aud': decoded.get('aud')
                })
            except Exception as err:
                print('Token debug error:', str(err))
        
        response = self.get_response(request)
        return response