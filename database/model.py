from mongoengine import *
from api.messages import *
from core.security.authentication import *
from database.controller import CRUD
from database.custom import *
import logging
import json


class User(BaseDocument):
    username = StringField(max_length=120, required=True, unique=True)
    password = PasswordStringField(max_length=120, required=True)
    test = EncryptedStringField(default="This is a test string")

    @classmethod
    async def createUser(cls, newUser: UserParams):
        msg = Message()
        crud = CRUD(cls=cls)
        try:
            crud.create(newUser, msg)
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def updateUser(cls, currentUser, newData: UserParams):
        msg = Message()
        crud = CRUD(cls=cls)
        try:
            currentUser = dict(currentUser)
            query = {"username": currentUser.get('username')}
            exclude = ['username', 'id']
            crud.read(query=query)
            crud.update(newData, msg, exclude=exclude)
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def deleteUser(cls, currentUser):
        msg = Message()
        crud = CRUD(cls=cls)
        try:
            currentUser = dict(currentUser)
            query = {"username": currentUser.get('username')}
            crud.read(query=query)
            crud.delete(msg)
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def authenticate(cls, inputCredentials: UserParams):
        msg = AuthMessage()
        try:
            msg = await check_password(dict(inputCredentials))
        except Exception as e:
            msg.authResult(False)
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def searchUser(cls, username: str, include_pwd: bool = False):
        data = []
        try:
            query = {"username": username, 'active': True}
            if include_pwd:
                data = cls.query(query=query)
            else:
                data = cls.query(exclude=['password'], query=query)
            data = data.to_dict()
        except Exception as e:
            logging.error(str(e))
        finally:
            return data

    @classmethod
    async def testSearch(cls):
        data = []
        try:
            query = {"username": 'as'}
            data = cls.query(exclude=['password'], query=query)
            if data:
                data = data.to_dict()
        except Exception as e:
            logging.error(str(e))
        finally:
            return data
