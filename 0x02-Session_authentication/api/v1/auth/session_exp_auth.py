#!/usr/bin/env python3
"""
Session Expiration Authentication module for the API
"""
import os
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """
    SessionExpAuth class that adds expiration to sessions
    """

    def __init__(self):
        """
        Initialize SessionExpAuth
        """
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', 0))
        except (ValueError, TypeError):
            self.session_duration = 0

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a Session ID for a user_id with expiration
        Args:
            user_id: User ID
        Returns:
            Session ID or None
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        # Create session dictionary with user_id and created_at
        session_dict = {
            'user_id': user_id,
            'created_at': datetime.now()
        }

        # Store the session dictionary
        self.user_id_by_session_id[session_id] = session_dict

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns a User ID based on a Session ID with expiration check
        Args:
            session_id: Session ID
        Returns:
            User ID or None
        """
        if session_id is None:
            return None

        session_dict = self.user_id_by_session_id.get(session_id)
        if session_dict is None:
            return None

        # If session_duration is 0 or less, session doesn't expire
        if self.session_duration <= 0:
            return session_dict.get('user_id')

        # Check if created_at exists
        created_at = session_dict.get('created_at')
        if created_at is None:
            return None

        # Check if session has expired
        expiration_time = created_at + timedelta(seconds=self.session_duration)
        if datetime.now() > expiration_time:
            return None

        return session_dict.get('user_id')
