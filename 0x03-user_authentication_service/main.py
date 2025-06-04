#!/usr/bin/env python3
"""End-to-end integration test for the authentication service."""

import requests


def register_user(email: str, password: str) -> None:
    """Test user registration.

    Args:
        email: User's email
        password: User's password
    """
    url = "http://localhost:5000/users"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)

    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Test login with wrong password.

    Args:
        email: User's email
        password: Wrong password
    """
    url = "http://localhost:5000/sessions"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)

    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """Test successful login.

    Args:
        email: User's email
        password: User's password

    Returns:
        str: Session ID
    """
    url = "http://localhost:5000/sessions"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)

    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "logged in"}

    return response.cookies.get("session_id")


def profile_unlogged() -> None:
    """Test profile access without login."""
    url = "http://localhost:5000/profile"
    response = requests.get(url)

    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Test profile access with valid session.

    Args:
        session_id: Valid session ID
    """
    url = "http://localhost:5000/profile"
    cookies = {"session_id": session_id}
    response = requests.get(url, cookies=cookies)

    assert response.status_code == 200
    assert "email" in response.json()


def log_out(session_id: str) -> None:
    """Test user logout.

    Args:
        session_id: Session ID to logout
    """
    url = "http://localhost:5000/sessions"
    cookies = {"session_id": session_id}
    response = requests.delete(url, cookies=cookies)

    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """Test password reset token generation.

    Args:
        email: User's email

    Returns:
        str: Reset token
    """
    url = "http://localhost:5000/reset_password"
    data = {"email": email}
    response = requests.post(url, data=data)

    assert response.status_code == 200
    json_response = response.json()
    assert json_response["email"] == email
    assert "reset_token" in json_response

    return json_response["reset_token"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test password update.

    Args:
        email: User's email
        reset_token: Valid reset token
        new_password: New password
    """
    url = "http://localhost:5000/reset_password"
    data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(url, data=data)

    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
