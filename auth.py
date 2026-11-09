
import hashlib
import hmac
import secrets

ITERATIONS = 310000

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS
    )

    return (
        f"{ITERATIONS}$"
        f"{salt.hex()}$"
        f"{password_hash.hex()}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        iterations, salt_hex, hash_hex = stored_hash.split("$")

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations)
        )

        return hmac.compare_digest(
            calculated_hash.hex(),
            hash_hex
        )

    except (ValueError, TypeError):
        return False
