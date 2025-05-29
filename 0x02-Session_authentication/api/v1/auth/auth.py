#!/usr/bin/env python3
"""
Authentication module for the API
"""
import os
from flask import request
from typing import List, TypeVar


class Auth:
    """
    Authentication class for managing API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Method to determine if a path requires authentication
        Args:
            path: Path to check
            excluded_paths: List of paths that don't need authentication
        Returns:
            True if authentication is required, False otherwise
        """
        if path is None or excluded_paths is None or not excluded_paths:
            return True

        # Ensure path ends with '/' for comparison
        path = path + '/' if path and path[-1] != '/' else path

        for excluded_path in excluded_paths:
            # Check for wildcard paths
            if excluded_path.endswith('*'):
                prefix = excluded_path[:-1]
                if path.startswith(prefix):
                    return False
            else:
                # Ensure excluded_path ends with '/' for comparison
                if excluded_path[-1] != '/':
                    excluded_path = excluded_path + '/'
                if path == excluded_path:
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Method to handle authorization header
        Args:
            request: Flask request object
        Returns:
            Authorization header value or None
        """
        if request is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Method to get current user
        """
        return None

    def session_cookie(self, request=None):
        """
        Returns a cookie value from a request
        Args:
            request: Flask request object
        Returns:
            Cookie value or None
        """
        if request is None:
            return None

        session_name = os.getenv('SESSION_NAME')
        if session_name is None:
            return None

        return request.cookies.get(session_name)
