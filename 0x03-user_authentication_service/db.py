#!/usr/bin/env python3
"""DB module for user database operations."""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User


class DB:
    """DB class for database operations."""

    def __init__(self) -> None:
        """Initialize a new DB instance."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object."""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database.

        Args:
            email: User's email address
            hashed_password: User's hashed password

        Returns:
            User: The newly created user object
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by arbitrary keyword arguments.

        Args:
            **kwargs: Arbitrary keyword arguments to filter by

        Returns:
            User: The first user found matching the criteria

        Raises:
            NoResultFound: When no user is found
            InvalidRequestError: When invalid query arguments are passed
        """
        try:
            user = self._session.query(User).filter_by(**kwargs).first()
            if user is None:
                raise NoResultFound()
            return user
        except TypeError:
            raise InvalidRequestError()

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update a user's attributes.

        Args:
            user_id: The ID of the user to update
            **kwargs: Arbitrary keyword arguments for attributes to update

        Raises:
            ValueError: When an invalid attribute is passed
        """
        user = self.find_user_by(id=user_id)

        for key, value in kwargs.items():
            if not hasattr(User, key):
                raise ValueError(f"User has no attribute {key}")
            setattr(user, key, value)

        self._session.commit()
