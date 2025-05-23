#!/usr/bin/env python3
"""
Module for password encryption and validation.
This module provides functionality to hash passwords securely
and validate them against stored hashes using bcrypt.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Returns a salted, hashed password as a byte string using bcrypt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates that the provided password matches the hashed password.
    Returns True if the password is valid, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
