from datetime import datetime
import yaml

def timestampToDate(input):
    try:
        ts = datetime.strptime(input, "%Y-%m-%dT%H:%M:%SZ")
        return datetime.date(ts)
    except:
        return None

def yamlToDict(pathToFile:str):
    with open(pathToFile) as f:
        return yaml.safe_load(f)