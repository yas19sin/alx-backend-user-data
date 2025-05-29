#!/usr/bin/env python3
"""
Session authentication views
"""
import os
from api.v1.views import app_views
from flask import abort, jsonify, request, make_response
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """
    POST /api/v1/auth_session/login
    Session authentication login
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if email is None or email == "":
        return jsonify({"error": "email missing"}), 400

    if password is None or password == "":
        return jsonify({"error": "password missing"}), 400

    # Search for user by email
    users = User.search({"email": email})
    if not users or len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]

    # Check password
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create session
    from api.v1.app import auth
    session_id = auth.create_session(user.id)
    if session_id is None:
        return jsonify({"error": "could not create session"}), 500

    # Create response with user data
    response = make_response(jsonify(user.to_json()))

    # Set cookie
    session_name = os.getenv('SESSION_NAME')
    if session_name:
        response.set_cookie(session_name, session_id)

    return response


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def session_logout():
    """
    DELETE /api/v1/auth_session/logout
    Session authentication logout
    """
    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)

    return jsonify({}), 200
