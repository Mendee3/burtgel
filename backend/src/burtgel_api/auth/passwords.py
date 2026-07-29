import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 120_000


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_value: str | None) -> bool:
    if not stored_value:
        return False
    try:
        salt, expected = stored_value.split("$", 1)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS).hex()
    return hmac.compare_digest(actual, expected)


PASSWORD_MIN_LENGTH = 12


def validate_password_policy(password: str) -> str:
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"хамгийн багадаа {PASSWORD_MIN_LENGTH} тэмдэгт")
    if any(char.isspace() for char in password):
        errors.append("зайгүй")
    if not any(char.islower() for char in password):
        errors.append("дор хаяж нэг жижиг үсэг")
    if not any(char.isupper() for char in password):
        errors.append("дор хаяж нэг том үсэг")
    if not any(char.isdigit() for char in password):
        errors.append("дор хаяж нэг тоо")
    if not any(not char.isalnum() for char in password):
        errors.append("дор хаяж нэг тусгай тэмдэгт")
    if errors:
        return "Нууц үгийн шаардлага хангаагүй байна: " + ", ".join(errors) + "."
    return ""
