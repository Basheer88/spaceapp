from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Company, Acheivment, Base

engine = create_engine('sqlite:///space.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create Company 1
Company1 = Company(name="Nasa", email="Nasa@nasa.com",
                   picture='http://t0.gstatic.com/images?q=tbn:ANd9GcQ9u48pu-6IB2FnnYl_H-15le_g8Dkt5d5RN-VWiWIl_-dyJdaa')
session.add(Company1)
session.commit()

# Acheivment 1
acheivment1 = Acheivment(company_id=1, title="First step on moon",
                         description='''Apollo 11 was the spaceflight that
                         landed the first two people on the Moon. Mission
                         commander Neil Armstrong and pilot Buzz Aldrin, both
                         American, landed the lunar module Eagle on July 20,
                         1969, at 20:17 UTC. Armstrong became the first person
                         to step onto the lunar surface six hours after landing
                         on July 21 at 02:56:15 UTC; Aldrin joined him about 20
                         minutes later. They spent about two and a quarter
                         hours together outside the spacecraft, and collected
                         47.5 pounds (21.5 kg) of lunar material to bring back
                         to Earth. Michael Collins piloted the command module
                         Columbia alone in lunar orbit while they were on the
                         Moon's surface. Armstrong and Aldrin spent 21.5 hours
                         on the lunar surface before rejoining Columbia in
                         lunar orbit.''')
session.add(acheivment1)
session.commit()

# Acheivment 2
acheivment2 = Acheivment(company_id=1, title="a mission to touch the sun",
                         description='''Wearing a nearly 5 inch coat of carbon
                         composite solar shields, NASA's Parker Solar Probe
                         will explore the sun's atmosphere in a mission that
                         is expected to launch in early August. This is NASA's
                         first mission to the sun and its outermost atmosphere,
                         called the corona. The spacecraft is buttoned up,
                         looking beautiful and ready for flight," Nicola Fox,
                         Parker Solar Probe project scientist at Johns Hopkins
                         Applied Physics Laboratory, said during a NASA press
                         conference Friday''')
session.add(acheivment2)
session.commit()

print "initial info added successfully"
