import hashlib


def generate_message_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def generate_message_hash_sha3(content: str) -> str:
    return hashlib.sha3_512(content.encode("utf-8")).hexdigest()


def verify_message_integrity(message_text: str, stored_hash: str) -> bool:
    if message_text is None:
        return True

    if not stored_hash:
        return False

    calculated_hash = generate_message_hash(message_text)
    return calculated_hash == stored_hash


def verify_message_integrity_sha3(message_text: str, stored_hash: str):
    if message_text is None:
        return None

    if not stored_hash:
        return None

    calculated_hash = generate_message_hash_sha3(message_text)
    return calculated_hash == stored_hash