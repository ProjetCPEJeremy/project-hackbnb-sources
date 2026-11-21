from typing import List
from database.init import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Mapped, mapped_column, relationship

class User(db.Model):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column()
    email: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str] = mapped_column()
    rooms: Mapped[List["Room"]] = relationship(back_populates="host_user")

    def __repr__(self):
        return f'<User {self.email!r}>'
    
    def to_dict(self):
        """Full representation, for the authenticated user themselves only."""
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
        }

    def to_public_dict(self):
        """Public representation exposed to other users (no PII such as email)."""
        return {
            "id": self.id,
            "name": self.name,
        }

    def set_password(self, clear_password: str):
        self.password_hash = generate_password_hash(clear_password)

    def is_valid_password(self, clear_password: str) -> bool:
        return check_password_hash(self.password_hash, clear_password)
