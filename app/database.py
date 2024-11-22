from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


DB_URL = "sqlite:///test.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})

session = sessionmaker(autoflush=False, autocommit=False, bind=engine)

Base = declarative_base() 