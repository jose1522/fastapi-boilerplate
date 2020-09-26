from mongoengine import *
from api.validation import *
from api.messages import *
from core.security.authentication import *
import json


class User(Document):
    username = StringField(max_length=120, required=True, unique=True)
    password = StringField(max_length=120, required=True)

    @classmethod
    async def createUser(cls, newUser: UserParams):
        msg = Message()
        try:
            doc = cls()
            newUser = dict(newUser)
            for key, value in newUser.items():
                if value is not None:
                    if key == 'password':
                        value = get_hashed_password(value)
                    doc.__setattr__(key, value)
            doc.save()
            msg.addMessage('Data', json.loads(doc.to_json()))
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def updateUser(cls, currentUser, newData: UserParams):
        msg = Message()
        try:
            newData = dict(newData)
            doc = cls.objects.get(username=currentUser.get('username'))
            for key, value in newData.items():
                if value is not None and key != 'username':
                    if key == 'password':
                        value = get_hashed_password(value)
                    doc.__setattr__(key, value)
            doc.save()
            msg.addMessage('Data', json.loads(doc.to_json()))
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def deleteUser(cls, currentUser):
        msg = Message()
        try:
            doc = cls.objects.get(username=currentUser.get('username'))
            doc.delete()
        except Exception as e:
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def authenticate(cls, inputCredentials: UserParams):
        msg = AuthMessage()
        try:
            msg = await check_password(inputCredentials)
        except Exception as e:
            msg.authResult(False)
            msg.addMessage('Error', str(e))
        finally:
            return msg.data

    @classmethod
    async def searchUser(cls, username: str):
        result = []
        try:
            result = cls.objects.get(username=username).to_json()
            result = json.loads(result)
        except Exception as e:
            print(str(e))
        finally:
            return result
