#!/usr/bin/env python3
"""
BasicAuth class to manage API authentication
"""
from api.v1.auth.auth import Auth
from models.user import User
import base64
from typing import TypeVar


class BasicAuth(Auth):
    """BasicAuth class to manage API authentication
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Return the Base64 part of the Authorization header
        """
        if (isinstance(authorization_header, str) and
                authorization_header.startswith('Basic ')):
            return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Return the decoded value of a Base64 string
        """
        try:
            return base64.b64decode(
                base64_authorization_header.encode('utf-8')).decode('utf-8')
        except Exception:
            return

    def extract_user_credentials(self, d: str) -> (str, str):
        """Return the user email and password from the Base64 decoded value
        """
        if (not isinstance(d, str) or ':' not in d):
            return (None, None)
        return (d[:d.find(':')], d[d.find(':') + 1:])

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Return the User instance based on email and password
        """
        if (user_email and user_pwd and isinstance(user_email, str) and
                isinstance(user_pwd, str)):
            try:
                users = User.search({'email': user_email})
            except Exception:
                return
            for u in users:
                if u.is_valid_password(user_pwd):
                    return u

    def current_user(self, request=None) -> TypeVar('User'):
        """Overload Auth and retrieve the User instance for a request
        """
        header = self.authorization_header(request)
        b64 = self.extract_base64_authorization_header(header)
        decode = self.decode_base64_authorization_header(b64)
        user, pwd = self.extract_user_credentials(decode)
        return self.user_object_from_credentials(user, pwd)
