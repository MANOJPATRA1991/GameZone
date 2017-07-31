from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


category1 = Category(name="Action")

session.add(category1)
session.commit()

category2 = Category(name="Action-Adventure")

session.add(category2)
session.commit()

category3 = Category(name="Adventure")

session.add(category3)
session.commit()

category4 = Category(name="Role-playing")

session.add(category4)
session.commit()

category5 = Category(name="Simulation")

session.add(category5)
session.commit()

category6 = Category(name="Strategy")

session.add(category6)
session.commit()

category7 = Category(name="Sports")

session.add(category7)
session.commit()
