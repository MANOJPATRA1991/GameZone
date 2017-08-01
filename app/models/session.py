from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
