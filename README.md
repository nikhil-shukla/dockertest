
# Web Configurations



## Description

This project is about moving from the File-based configurations to Schema/table-based configurations. It is built using FastAPI and SQLAlchemy with an SQLite database for data storage.

## Requirements

To run this project, you need the following:

- **Python**: Version 3.12.0
- **FastAPI**: A modern, fast (high-performance) web framework for building APIs with Python 3.6+.
- **SQLAlchemy**: A SQL toolkit and Object-Relational Mapping (ORM) system for Python.
- **SQLite**: A lightweight database that is easy to set up and use.

## Installation Steps

Follow these steps to set up and run the project:

### 1. Clone the Repository

Open your terminal and run the following command to clone the repository:

```bash
git clone https://socgit.advantest.com/bitbucket/scm/socmt/socmt_ames_config.git
cd socmt_ames_config
```

### 2. Create a Virtual Environment

```bash
python -m venv venv

```


#### Activate the virtual environment

###### On Windows
```bash
venv\Scripts\activate
```
###### On macOS/Linux
```bash
source venv/bin/activate
```

### 3. Install Required Packages

```bash
pip install -r requirements.txt
```

### 4. Running the Application
To run the FastAPI application, use the following command:
```bash
uvicorn main:app --reload
```

### 4. Running db_setup.py
This step is to crate a super user after app is up and running.
```bash
python db_setup.py
```
### 5. Access the Application
Open your web browser and go to  [localhost:8000/admin](http://localhost:8000/admin/) and login with yeray.ferrer-garcia@advantest.com as a Super-User Admin.


## Project Structure

Here's a suggested directory structure for your project:
```bash
/your_project
│
├── main.py                # Main application file
├── models.py              # pydantic models 
├── schema.py              # SQLAlchemy models
├── database.py            # Database connection setup
├── db_setup.py            # Create SuperUSer in DB
├── .gitignore             # Git ignore to skip unwanted files
├── requirements.txt       # List of dependencies
└── README.md              # Project documentation
```
