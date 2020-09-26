from core import app  # Imports the "app" object from __init__.py, located in the core folder.

if __name__ == "__main__":
    app.run()  # runs the flask core through "Lazy loading" (not through a real server)