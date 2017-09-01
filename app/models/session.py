from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base

engine = create_engine('postgresql://catalog:catalog@dbuser/catalog')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
