from sqlalchemy import (Column, ForeignKey, Integer,
                        String, Boolean, DateTime, func)

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serializer,
    BadSignature, SignatureExpired)
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
