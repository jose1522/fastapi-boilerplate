# Description

This is a template for creating a web application using python and flask as a backend.

## Instalation

You need to install the requirements from the txt file, as well as redis (use brew for mac). In addition, you need to create a .env file with the environment variables.

```bash
pip install -r requirements.txt
brew install redis
```

## Usage

Run the "run.py" file and the redis server on the default host/port
```python
python3 run.py
redis-server
```