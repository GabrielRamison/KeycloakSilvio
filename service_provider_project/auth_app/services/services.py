# service_provider/auth_app/services.py
import requests
from django.conf import settings

class KeycloakService:
    @staticmethod
    def get_user_info(access_token):
        try:
            response = requests.get(
                f"{settings.INTERNAL_KEYCLOAK_URL}/auth/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/userinfo",
                headers={'Authorization': f'Bearer {access_token}'}
            )
            response.raise_for_status()
            return response.json()
        except Exception as error:
            print("Error fetching user info:", str(error))
            raise ValueError("Failed to fetch user info")