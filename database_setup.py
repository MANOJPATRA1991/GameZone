from sqlalchemy import (Column, ForeignKey, Integer,
                        String, Boolean, DateTime, func)

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

from passlib.apps import custom_app_context as pwd_context

from itsdangerous import (
    TimedJSONWebSignatureSerializer as
    Serializer, BadSignature, SignatureExpired)

import random
import string

Base = declarative_base()

secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in range(32))


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    picture = Column(String(250))
    email = Column(String(250), nullable=False)
    admin = Column(Boolean, default=False)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'picture': self.picture,
            'email': self.email,
            'admin': self.admin
        }


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String)

    @property
    def serialize(self):
        return {
            'category_id': self.id,
            'category_name': self.name
        }


class Games(Base):
    __tablename__ = 'games'
    id = Column(Integer, primary_key=True)
    name = Column(String(250))
    release_date = Column(DateTime)
    description = Column(String(4096))
    image_path = Column(String(500))
    banner_path = Column(String(500))
    video_path = Column(String(500))
    platform = Column(String(100))
    creators = Column(String(100))
    created = Column(DateTime, default=func.now())
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # Add a property decorator to serialize information from this database
    @property
    def serialize(self):
        return {
            'name': self.name,
            'release_date': self.release_date,
            'platform': self.platform,
            'creators': self.creators,
            'description': self.description,
            'image_path': self.image_path,
            'banner_path': self.banner_path,
            'video_path': self.video_path,
            'created': self.created,
            'category': self.category_id,
            'id': self.id,
            'user_id': self.user_id
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
