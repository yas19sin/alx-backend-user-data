#!/usr/bin/env python3
"""
Basic Authentication module for the API
"""
import base64
from typing import TypeVar

from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
    BasicAuth class that inherits from Auth
    """

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """
        Extracts the Base64 part from the Authorization header
        Args:
            authorization_header: Authorization header
        Returns:
            The Base64 part of the Authorization header, None otherwise
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Decodes the Base64 authorization header

        Args:
            base64_authorization_header: The Base64 authorization header

        Returns:
            The decoded value as a UTF8 string, None otherwise
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded = base64.b64decode(base64_authorization_header)
            return decoded.decode("utf-8")
        except Exception:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """
        Extracts user credentials from decoded Base64 authorization header

        Args:
            decoded_base64_authorization_header: Decoded Base64 header

        Returns:
            Tuple (user email, password) or (None, None)
        """
        if decoded_base64_authorization_header is None:
            return (None, None)

        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)

        if ":" not in decoded_base64_authorization_header:
            return (None, None)

        # Split only at the first occurrence of ':'
        email, pwd = decoded_base64_authorization_header.split(":", 1)
        return (email, pwd)

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """
        Returns the User instance based on email and password

        Args:
            user_email: User's email
            user_pwd: User's password

        Returns:
            User instance if valid credentials, None otherwise
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})
        except Exception:
            return None

        if not users or len(users) == 0:
            return None

        user = users[0]

        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar("User"):
        """
        Retrieves the User instance for a request

        Args:
            request: Flask request object

        Returns:
            User instance if valid credentials, None otherwise
        """
        if request is None:
            return None

        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None

        base64_auth_header = self.extract_base64_authorization_header(
            auth_header
        )
        if base64_auth_header is None:
            return None

        decoded_auth_header = self.decode_base64_authorization_header(
            base64_auth_header
        )
        if decoded_auth_header is None:
            return None

        user_email, user_pwd = self.extract_user_credentials(
            decoded_auth_header
        )
        if user_email is None or user_pwd is None:
            return None

        return self.user_object_from_credentials(user_email, user_pwd)
