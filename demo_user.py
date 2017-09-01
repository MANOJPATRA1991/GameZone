from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User

# Create engine to connect to catalog database
engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# Create Admin
user1 = User(name="Admin", email="admin@admin.com", admin=True)

# Add admin to session
session.add(user1)

# Commit Admin to database
session.commit()

user1.hash_password("admin")
session.add(user1)
session.commit()
