from pathlib import Path

from sqlalchemy import Column, Float, Integer, String, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[1]
DATABASE_PATH = BASE_DIR / "netwatch.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)


class DeviceInfo(Base):
    __tablename__ = "devices_info"

    mac = Column(String(32), primary_key=True, index=True)
    ip = Column(String(64), nullable=True)
    custom_name = Column(String(255), nullable=True)
    area = Column(String(128), default="Sin Asignar", nullable=False)
    admin_user = Column(String(128), nullable=True)
    admin_pass = Column(String(128), nullable=True)
    parent_mac = Column(String(32), nullable=True)
    pos_x = Column(Float, nullable=True)
    pos_y = Column(Float, nullable=True)


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # create_all does not add columns to existing SQLite tables.
    columns = {column["name"] for column in inspect(engine).get_columns("devices_info")}
    if "parent_mac" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE devices_info ADD COLUMN parent_mac VARCHAR(32)"))
