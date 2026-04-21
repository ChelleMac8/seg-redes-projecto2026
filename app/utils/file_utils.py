ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "mp3", "wav", "ogg", "m4a"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_type(filename):
    ext = filename.rsplit(".", 1)[1].lower()

    if ext in {"png", "jpg", "jpeg", "gif", "webp"}:
        return "image"

    if ext in {"mp3", "wav", "ogg", "m4a"}:
        return "audio"

    return None