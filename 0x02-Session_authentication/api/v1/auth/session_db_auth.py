#!/usr/bin/env python3
"""
SessionDBAuth class to manage API authentication
"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from os import getenv
from datetime import datetime, timedelta


class SessionDBAuth(SessionExpAuth):
    """SessionExpAuth class to manage API authentication
    """

    def create_session(self, user_id=None):
        """Create session
        """
        if user_id:
            session_id = super().create_session(user_id)
            us = UserSession(user_id=user_id, session_id=session_id)
            us.save()
            UserSession.save_to_file()
            return session_id

    def user_id_for_session_id(self, session_id=None):
        """Get user ID from session
        """
        if not session_id:
            return None
        UserSession.load_from_file()
        users = UserSession.search({'session_id': session_id})
        for u in users:
            delta = timedelta(seconds=self.session_duration)
            if u.created_at + delta < datetime.now():
                return None
            return u.user_id

    def destroy_session(self, request=None):
        """Delete the user session / log out
        """
        if request:
            session_id = self.session_cookie(request)
            if not session_id:
                return False
            if not self.user_id_for_session_id(session_id):
                return False
            users = UserSession.search({'session_id': session_id})
            for u in users:
                u.remove()
                UserSession.save_to_file()
                return True
        return False
