from core.security.sanitizer import Sanitizer
from core.security.authentication import get_hash
from core.security.encryption import Cipher, EncryptedString, HashedString
from mongoengine import StringField, BooleanField, Document, DateField, QuerySet, queryset_manager
from datetime import datetime
import logging
import json


class SanitizedStringField(StringField):
    def to_mongo(self, value):
        if value:
            value = Sanitizer.sanitize(value)
        # value = super(SanitizedStringField, self).to_mongo(value)
        return value


class PasswordStringField(StringField):
    def to_mongo(self, value):
        if value and not isinstance(value, HashedString):
            value = get_hash(value)
        return value

    def to_python(self, value):
        if value:
            value = HashedString(value)
        return value


class EncryptedStringField(StringField):
    def to_mongo(self, value):
        if value and not isinstance(value, EncryptedString):
            value = Cipher.encryptString(value)
        return value

    def to_python(self, value):
        if value:
            value = Cipher.decryptString(value)
        return value


class BaseDocument(Document):
    active = BooleanField(default=True)
    createdOn = DateField(default=datetime.today())
    deletedOn = DateField()

    meta = {
        'abstract': True
    }

    @queryset_manager
    def query(cls,
              queryset,
              query: dict,
              sortParams: list = None,
              limit: int = None,
              skip: int = None,
              exclude: list = None,
              only: list = None,
              ):

        data = queryset.filter(**query)

        if skip is not None:
            data = data.skip(skip)

        if limit is not None:
            data = data.limit(limit)

        if sortParams is not None:
            data = data.order_by(*sortParams)

        if exclude is not None:
            data = data.exclude(*exclude)

        if only is not None:
            data = data.only(*only)

        try:
            data = data.get()
        except:
            data = data.all()
        finally:
            return data

    def to_dict(self):
        return json.loads(self.to_json())