from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


user1 = User(name="Admin", email="admin@admin.com", admin=True)
session.add(user1)
session.commit()

user1.hash_password("admin")
session.add(user1)
session.commit()
