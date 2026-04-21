import uuid
import hashlib
from flask import session


def generate_user_hash():
    raw = str(uuid.uuid4())
    return hashlib.sha256(raw.encode()).hexdigest()


def require_login():
    return "user_id" in session