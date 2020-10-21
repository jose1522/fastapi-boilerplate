from core.security.sanitizer import Sanitizer
from core.security.authentication import get_hash
from core.security.encryption import Cipher, EncryptedString, HashedString
from mongoengine import StringField, BooleanField, Document, DateField, QuerySet, queryset_manager
from database.controller import CRUD
from api.messages import Message
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
    @classmethod
    async def createRecord(cls, **kwargs):
        msg = Message()
        crud = CRUD(cls=cls)
        try:
            crud.create(kwargs, msg)
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def searchWithParams(cls, skip, limit, **kwargs) -> dict:
        data = None
        crud = CRUD(cls=cls)
        try:
            kwargs["active"] = True
            crud.read(query=kwargs, skip=skip, limit=limit, exclude=['createdOn', 'active'])
            data = crud.toJSON()
        except Exception as e:
            logging.error(str(e))
        finally:
            return data

    @classmethod
    async def deleteRecord(cls, objectID: str) -> None:
        msg = Message()
        crud = CRUD(cls=cls)
        try:
            query = {"id": objectID, 'active': True}
            crud.read(query=query)
            crud.delete(msg)
        except Exception as e:
            raise e

    @classmethod
    async def updateRecord(cls, **kwargs):
        msg = Message()
        crud = CRUD(cls=cls)
        try:
            query = {"id": kwargs.get('id'), 'active': True}
            exclude = ['id']
            crud.read(query=query)
            crud.update(kwargs, msg, exclude=exclude)
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

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