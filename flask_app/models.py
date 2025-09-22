"""
Database models and utilities.

This module defines the `User` class used by Flask‑Login to represent
authenticated users. It encapsulates the logic for interacting with the
Supabase backend and generating/verifying password reset tokens. Storing
passwords as hashes protects against data breaches by ensuring that
plaintext passwords are never persisted【775746537229351†L349-L363】.

Reset tokens are implemented as JSON Web Tokens (JWT) with an
expiration timestamp. The payload encodes the user's unique identifier and
expires after a configurable number of seconds【418069725510074†L313-L324】.
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
import jwt
from flask import current_app
from flask_login import UserMixin
from werkzeug.security import check_password_hash


class User(UserMixin):
    """Represents an authenticated user.

    Instances of this class should be constructed from database rows. All
    attributes are stored as plain Python attributes. The class provides
    static methods to look up and create users in the Supabase table named
    `users`.
    """

    # Supabase client is assigned from the application factory
    supabase = None

    def __init__(self, id: Any, username: str, email: str, password_hash: str):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash

    # Flask‑Login expects a get_id() method that returns a unicode string
    def get_id(self):  # type: ignore[override]
        return str(self.id)

    @classmethod
    def from_row(cls, row: dict) -> 'User':
        """Create a `User` instance from a database row."""
        return cls(row['id'], row['username'], row['email'], row['password_hash'])

    @classmethod
    def get(cls, user_id: Any) -> Optional['User']:
        """Retrieve a user by primary key.

        Returns None if the user is not found or if the Supabase client is
        not configured.
        """
        if not cls.supabase:
            return None
        try:
            response = cls.supabase.table('users').select('*').eq('id', user_id).single().execute()
            data = getattr(response, 'data', None)
            if data:
                return cls.from_row(data)
        except Exception:
            # Could log or handle error here
            pass
        return None

    @classmethod
    def get_by_username(cls, username: str) -> Optional['User']:
        if not cls.supabase:
            return None
        try:
            response = cls.supabase.table('users').select('*').eq('username', username).single().execute()
            data = getattr(response, 'data', None)
            if data:
                return cls.from_row(data)
        except Exception:
            pass
        return None

    @classmethod
    def get_by_email(cls, email: str) -> Optional['User']:
        if not cls.supabase:
            return None
        try:
            response = cls.supabase.table('users').select('*').eq('email', email).single().execute()
            data = getattr(response, 'data', None)
            if data:
                return cls.from_row(data)
        except Exception:
            pass
        return None

    @classmethod
    def create(cls, username: str, email: str, password_hash: str) -> Optional['User']:
        """Insert a new user record and return a User instance.

        Returns None if the insert fails.
        """
        if not cls.supabase:
            return None
        try:
            insert_data = {
                'username': username,
                'email': email,
                'password_hash': password_hash,
            }
            response = cls.supabase.table('users').insert(insert_data).execute()
            data = getattr(response, 'data', None)
            if data:
                # Supabase returns a list of inserted rows
                return cls.from_row(data[0])
        except Exception:
            pass
        return None

    @classmethod
    def update_password(cls, user_id: Any, new_password_hash: str) -> bool:
        """Update the hashed password for a user.

        Returns True on success, False otherwise.
        """
        if not cls.supabase:
            return False
        try:
            response = cls.supabase.table('users').update({'password_hash': new_password_hash}).eq('id', user_id).execute()
            # If one record was updated, the update succeeded
            updated = getattr(response, 'data', None)
            return bool(updated)
        except Exception:
            return False

    # Password reset token methods inspired by the Flask Mega‑Tutorial【418069725510074†L313-L324】
    def get_reset_password_token(self, expires_in: int = 600) -> str:
        """Generate a JWT token that can be used to reset the user's password.

        The token payload includes the user's primary key and an expiration
        timestamp. The secret key used to sign the token is the Flask
        application's SECRET_KEY. A default expiration of 600 seconds (10
        minutes) is used but can be overridden.
        """
        now = datetime.now(timezone.utc)
        payload = {
            'reset_password': self.id,
            'exp': now + timedelta(seconds=expires_in),
        }
        secret_key = current_app.config['SECRET_KEY']
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        # In PyJWT >= 2.0 the result is a str; cast to str for consistency
        return token if isinstance(token, str) else token.decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token: str) -> Optional['User']:
        """Verify a JWT reset token and return the associated user or None.

        This method decodes the token using the Flask application's secret
        key. If the signature is valid and the token has not expired,
        the user's ID is extracted and used to look up the user in the
        database. Invalid or expired tokens result in None being returned
        without raising an exception【418069725510074†L313-L324】.
        """
        try:
            secret_key = current_app.config['SECRET_KEY']
            decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
            user_id = decoded.get('reset_password')
        except Exception:
            return None
        return User.get(user_id)