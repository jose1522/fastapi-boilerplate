import requests
import json


class API:
    def __init__(self, url: str, method: str="GET"):
        self._url = url
        self.method = method
        self._headers = {}
        self.response = None
        self.data = ''
        super().__init__()

    def addToHeaders(self, key, value):
        self._headers.update({key: value})

    def addDictToHeaders(self, myDict: dict):
        for key, value in myDict.items():
            self.addToHeaders(key,value)

    def setData(self, dataString: str):
        self.data = dataString

    def sendCall(self):
        try:
            if self.data != '':
                response = requests.request(self.method, self._url, headers=self._headers, data=self.data)
            else:
                response = requests.request(self.method, self._url, headers=self._headers)
            status_code = (response.status_code if response.status_code else 'NA')
            text = (json.loads(response.text) if response.text else 'NA')
            return status_code, text
        except Exception as e:
            print("Error fetching data: ", str(e))