#!/usr/bin/env python3
"""
Session Authentication module for the API
"""
import uuid
from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """
    SessionAuth class that inherits from Auth
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a Session ID for a user_id
        Args:
            user_id: User ID
        Returns:
            Session ID or None
        """
        if user_id is None:
            return None

        if not isinstance(user_id, str):
            return None

        # Generate a Session ID using uuid4()
        session_id = str(uuid.uuid4())

        # Store user_id with session_id as key
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns a User ID based on a Session ID
        Args:
            session_id: Session ID
        Returns:
            User ID or None
        """
        if session_id is None:
            return None

        if not isinstance(session_id, str):
            return None

        # Return the value for the key session_id using .get()
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Returns a User instance based on a cookie value
        Args:
            request: Flask request object
        Returns:
            User instance or None
        """
        from models.user import User

        if request is None:
            return None

        # Get session ID from cookie
        session_id = self.session_cookie(request)
        if session_id is None:
            return None

        # Get user ID from session ID
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return None

        # Get User instance from database
        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Deletes the user session / logout
        Args:
            request: Flask request object
        Returns:
            True if session was destroyed, False otherwise
        """
        if request is None:
            return False

        # Get session ID from cookie
        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        # Check if session ID is linked to any User ID
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False

        # Delete the session ID from the dictionary
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
            return True

        return False
