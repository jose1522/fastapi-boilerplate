import enum
import core.util.parsers as customParsers
import core.util.dictTools as dictTools
import core.integration.apiConnection as api
import json


# List of the categories from the configuration file
class EmailCategory(enum.Enum):
    signUp = 0
    signUpConfirmation = 0
    recoverPassword = 0


class Email:

    def __init__(self, emailCategory: EmailCategory):
        if isinstance(emailCategory, EmailCategory):
            self.category = emailCategory.name
            self.recipients = []
            self.personalizations = []
            self.subject = ""
            self.content = {}
            self.dynamicData = {}
            self.sender = {}
            self.data = customParsers.yamlToDict("core/objects/confFiles/SendGrid_Data.yaml")
            self.templateId = emailCategory.value
            self.sg = api.API("https://api.sendgrid.com/v3/mail/send", method="POST")
            self.__addDataFromConfigFile()
        else:
            raise Exception("Parameter is not of type EmailCategory")

    def __addDataFromConfigFile(self):
        # Gets keys from all the document
        presetDynamicData = customParsers.yamlToDict("core/objects/confFiles/Email_Templates.yaml")
        presetDynamicElements = list(presetDynamicData.keys())
        if self.category in presetDynamicElements:  # Checks if the enum exists in the conf document
            try:
                categoryData = presetDynamicData.get(self.category)  # Extracts the category's data
                categoryElements = list(categoryData.keys())

                # Step 1 - Add dynamic data from yaml file
                self.dynamicData.update(categoryData.get("dynamicData"))

                # Step 2 - Add sender data from yaml file
                if "from" in categoryElements:  # Checks if there is custom sender data for the category
                    senderData = categoryData.get("from")

                    # Step 2.1 - Check if the structure is correct
                    if self.__checkSenderObjectStructure(senderData):
                        self.sender = senderData
                    else:
                        raise Exception(
                            'Sender data from category configuration has incorrect structure. Correct structure has only name and email')

                # Step 3 - Add template id from yaml file
                self.templateId = categoryData.get("id")  # Extracts the template id

                # Step 4 - Add subject from yaml file
                self.subject = categoryData.get("subject")  # Extracts the subject

            except:
                raise Exception(
                    "There was an error in the email configuration file for category {0}".format(self.category))
        else:
            raise Exception("The enum name provided does not exist in the Email Template configuration file")

    def __checkSenderObjectStructure(self, senderData: dict):
        sampleDict = {"name": "name", "email": "email"}
        return dictTools.doDictStructuresMatch(senderData, sampleDict)

    def __prepareData(self):
        # Replace sender if not empty
        if len(self.sender) > 0: self.data["from"] = self.sender

        # Add template id
        self.data["template_id"] = str(self.templateId)

        # Create and add personalizations to data
        self.content.update({"dynamic_template_data": self.dynamicData})
        self.content.update({"subject": self.subject})
        self.content.update({"to": self.recipients})
        self.personalizations.append(self.content)
        self.data['personalizations'] = self.personalizations

    def addDynamicData(self, key, value):
        self.dynamicData.update({key: value})

    def addRecipient(self, name, email):
        self.recipients.append({"name": name, "email": email})

    def send(self):
        self.__prepareData()
        self.sg.addToHeaders("Authorization", "Bearer " + app.config.get("SENDGRID_KEY"))
        self.sg.addToHeaders("content-type", "application/json")
        self.sg.setData(json.dumps(self.data))
        status, text = self.sg.sendCall()
        return status, text
