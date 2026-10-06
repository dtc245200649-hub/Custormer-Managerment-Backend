import re
from getpass import getpass

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select

from app.database import Base, SessionLocal, engine
from app.models import User
from app.security import hash_password

ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def main() -> None:
    Base.metadata.create_all(bind=engine)
    try:
        email = str(TypeAdapter(EmailStr).validate_python(input("Email: ").strip())).lower()
    except ValidationError as error:
        raise SystemExit(f"Email không hợp lệ: {error}") from error
    role = input("Role (lowercase, e.g. admin or staff): ").strip().lower()
    if not ROLE_PATTERN.fullmatch(role):
        raise SystemExit("Role chỉ được gồm chữ thường, số, dấu gạch ngang hoặc gạch dưới.")
    password = getpass("Password (ít nhất 8 ký tự): ")
    if len(password) < 8:
        raise SystemExit("Mật khẩu phải có ít nhất 8 ký tự.")

    with SessionLocal() as db:
        if db.scalar(select(User.id).where(User.email == email)) is not None:
            raise SystemExit("Email này đã tồn tại.")
        db.add(User(email=email, password_hash=hash_password(password), role=role))
        db.commit()
    print(f"Đã tạo tài khoản {email} với role {role}.")


if __name__ == "__main__":
    main()
