#!/usr/bin/env python3
"""
Session Database Authentication module for the API
"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """
    SessionDBAuth class that stores sessions in database
    """

    def create_session(self, user_id: str = None) -> str:
        """
        Creates and stores a new instance of UserSession
        Args:
            user_id: User ID
        Returns:
            Session ID or None
        """
        if user_id is None:
            return None

        if not isinstance(user_id, str):
            return None

        # Generate a Session ID using parent class
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        # Create and save UserSession instance
        user_session = UserSession(user_id=user_id, session_id=session_id)
        user_session.save()

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns the User ID by requesting UserSession in the database
        Args:
            session_id: Session ID
        Returns:
            User ID or None
        """
        if session_id is None:
            return None

        if not isinstance(session_id, str):
            return None

        try:
            # Search for UserSession by session_id
            user_sessions = UserSession.search({'session_id': session_id})
            if not user_sessions or len(user_sessions) == 0:
                return None

            user_session = user_sessions[0]
            return user_session.user_id
        except Exception:
            return None

    def destroy_session(self, request=None) -> bool:
        """
        Destroys the UserSession based on the Session ID from request cookie
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

        try:
            # Search for UserSession by session_id
            user_sessions = UserSession.search({'session_id': session_id})
            if not user_sessions or len(user_sessions) == 0:
                return False

            # Remove the UserSession from database
            user_session = user_sessions[0]
            user_session.remove()
            return True
        except Exception:
            return False
