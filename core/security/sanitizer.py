import bleach


class Sanitizer:
    ALLOWED_TAGS = []
    ALLOWED_ATTRS = {}
    ALLOWED_STYLES = []

    @classmethod
    def sanitize(cls, content):
        return bleach.clean(
            content,
            tags=cls.ALLOWED_TAGS,
            attributes=cls.ALLOWED_ATTRS,
            styles=cls.ALLOWED_STYLES)