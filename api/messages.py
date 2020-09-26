
class Message:
    def __init__(self):
        self.data = {}

    def addMessage(self, key, value):
        self.data.update({key: value})


class AuthMessage(Message):
    def __init__(self):
        super().__init__()

    def authResult(self, result: bool):
        self.addMessage('Result', result)
