import sqlite3
from fastapi import FastAPI, HTTPException, Depends, Request, Form, Response, status, Security, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime
from enum import Enum
from typing import Optional
from fastapi.templating import Jinja2Templates
from sqlalchemy import Select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError, ProgrammingError
import schema
import logging.config
from models import *
from database import engine, session
from sqlalchemy.orm import Session
from sqlalchemy.future import select
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired
from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from wtforms.widgets import TextInput
from markupsafe import  Markup
from passlib.context import CryptContext
from io import StringIO
import csv


#           ===================================================
#                           Initial Configs
#           ===================================================

security = HTTPBasic()

pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")


# Logging config


logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - [ %(levelname)s ]  - %(name)s - %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': 'app.log',
            'formatter': 'standard',
        },
    },
    'loggers': {
        'web_config': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
})

logger = logging.getLogger("web_config")


#  creates db and tables if it not ecists
schema.Base.metadata.create_all(bind=engine)

# Set up Jinja2 templates
templates = Jinja2Templates(directory="templates")

# app = FastAPI(dependencies=[Depends(security)])
app = FastAPI()



#           ===================================================
#                     Helper Functions
#           ===================================================




def handle_db_errors(db, error: Exception):
    try:
        db.rollback()  # Attempt to rollback
    except Exception as rollback_error:
        logger.error(f"Rollback Error occure while handling another error: {rollback_error}")
    
    if isinstance(error, IntegrityError):
        logger.error(f"IntegrityError: {error}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail="Integrity error occurred while fetching products!\
                                  This usually happens when a database integrity constraint is violated.")
    elif isinstance(error, OperationalError):
        logger.error(f"OperationalError: {error}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                             detail="Database operational error occurred while fetching products!\
                                This can occur due to issues like connection problems or database unavailability.")
    elif isinstance(error, ProgrammingError):
        logger.error(f"ProgrammingError: {error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                             detail="Programming error occurred while fetching products!\
                                  This typically indicates an error in the SQL syntax or a reference to a non-existent table or column.")
    elif isinstance(error, SQLAlchemyError):
        logger.error(f"SQLAlchemyError: {error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                             detail="A database error occurred while fetching products!\
                                  This encompasses a variety of SQLAlchemy-related errors.")
    else:
        logger.error(f"Unexpected error: {error}")
        raise HTTPException(status_code=error.status_code, detail=f"{error}")


# Function to hash passwords
def hash_password(password: str):
    return pwd_context.hash(password)

# Function to verify passwords
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# get DB session
def get_db():
    try:
        db = session()
        yield db
    except Exception as e:
        handle_db_errors(db, e)
    finally:
        db.close()


def authenticate_user(credentials: HTTPBasicCredentials, db: Session = Depends(get_db)):
    user = db.query(schema.User).filter(schema.User.email == credentials.username).first()
    if user is None or not verify_password(credentials.password, user.password):
    # if user is None or ( not user.is_admin or not user.is_superuser ):  # Check if user exists and is an admin
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


def get_user_email_enum(db: Session):
    users = db.query(schema.User).all()
    return Enum('UserEmail', {user.email: user.email for user in users})


def validate_user_email(user_mail: EmailStr, db: Session):
    user = db.query(schema.User).filter(schema.User.email == user_mail).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email {user_mail} not found."
        )
    

def validate_product_exists(prod_name: str, db: Session):
    prod = db.query(schema.Product).filter(schema.Product.product_name == prod_name).first()
    if not prod:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with name:'{prod_name}' not found."
        )



def is_file_type_csv(file: UploadFile):

    type = file.content_type
    if not type or type.split("/")[-1] != "csv":
        return False
    if not file.filename.endswith('.csv'):
        return False
    logger.info(f"{file.filename} is a valid file !")
    return True



def convert_value(value: str):
    """Convert string values to their appropriate types."""

    # Handle boolean conversion
    if value.lower() == 'true':
        return True
    elif value.lower() == 'false':
        return False
    
    # Handle integer conversion
    try:
        return int(value)
    except ValueError:
        pass  # If it can't be converted to int, continue checking

    # Handle float conversion
    try:
        return float(value)
    except ValueError:
        pass  

    # Handle datetime conversion (format: YYYY-MM-DD HH:MM:SS)
    try:
        return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        pass  

    return value


def valid_model_rows(db:Session, reader, pydantic_model):
    errors = []
    valid_rows = []
    logger.info("Validataing rows of file !")
    # Process each row in the CSV file
    for row in reader:
        try:
            converted_row = {key: convert_value(value) for key, value in row.items()}
            # Validate the row against the Pydantic model
            test_cell = pydantic_model(**converted_row,context= {'db_session': db})
            # del test_cell["context"]
            valid_rows.append(test_cell.model_dump())
        except ValueError as e:
            # Capture validation errors
            errors.append(f"Row {reader.line_num}: {str(e)}")
    return errors, valid_rows
    

def insert_data(db:Session, db_schema, valid_rows):
    try:
        for row_data in valid_rows:
            file_explorer_tab = db_schema(**row_data)
            db.add(file_explorer_tab)
        db.commit()
        logger.info("File proccess and inserted data into DB !")
        return {"message": "File processed and data inserted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error inserting data into the database")


#           ===================================================
#                           Admin App Starts
#           ===================================================

class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        username, password = form["username"], form["password"]
        user = authenticate_user(HTTPBasicCredentials(username=username, password=password), session())
        request.session.update({"token": username, "is_admin": user.is_admin, "is_autoftsuser":user.is_autoftsuser,
                                "is_superuser":user.is_superuser})
        request.state.user = user
        return True

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        # request.user = "None"
        return True

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")

        if not token:
            return False

        # Check the token in depth
        return True

authentication_backend = AdminAuth(secret_key="random")
admin = Admin(app, engine, authentication_backend=authentication_backend, title="Advantest Admin Config app")


class UserAdmin(ModelView, model=schema.User):
    column_list = [schema.User.created_products,schema.User.modified_products ,
                   schema.User.email,schema.User.username, schema.User.is_admin, schema.User.is_autoftsuser,
                     schema.User.is_superuser]
    icon = "fa-solid fa-user"
    form_columns = [schema.User.email,schema.User.username,schema.User.password, schema.User.is_admin, schema.User.is_autoftsuser,
                     schema.User.is_superuser]
    form_widget_args = {
        'username': {
            'class': 'form-control',  # Add Bootstrap class to the input field
            'placeholder': 'Enter your Username',  # Add a placeholder
            "title": "username here",
        }
    }
    async def on_model_change(self, form, user: schema.Product, is_created: bool, request: Request):
        # Validate the created_by field
        session: Session = self.session_maker()
        if is_created:
            form["password"] = hash_password(form.get("password"))
        else:
            form["password"] = hash_password(form.get("password"))


    def is_visible(self, request: Request) -> bool:
        superuser = request.session.get("is_superuser")
        if superuser:
            self.can_edit = True
            self.can_delete = True
            self.can_view_details = True
            self.can_create = True
        else:
            self.can_edit = False
            self.can_delete = False
            self.can_view_details = False
            self.can_create = False
        return True


    def is_accessible(self, request: Request) -> bool:
        superuser = request.session.get("is_superuser")
        return True if superuser else False


class ProductAdmin(ModelView, model=schema.Product):
    icon = "fa-solid fa-gears"
    form_columns = [schema.Product.site,
                    schema.Product.product_name,
                    # schema.Product.contract_manufacturer, schema.Product.test_site,
                    schema.Product.path_fail_level,
                    schema.Product.path_repair_list, schema.Product.mrun_input, schema.Product.mod_count, schema.Product.mod_channel_count,
                    schema.Product.has_fib, schema.Product.has_bib, schema.Product.has_pcon, schema.Product.sys_cc_count, schema.Product.sys_slot_count
                    ]
    column_exclude_list = ["id"]
    column_details_exclude_list = [
        "id",
        schema.Product.created_by,
        schema.Product.modified_by,
        schema.Product.site_name,
        ]
    form_widget_args = {
        'site_name': {
            'class': 'form-control', 
            'placeholder': 'Select site name here.',  # Add a placeholder
            "title": "CM Site",
            "data-toggle":"tooltip"
        },
        'product_name': {
            'class': 'form-control', 
            'placeholder': 'Enter product name here.',  # Add a placeholder
            "title": "Name of the Product",
            "data-toggle":"tooltip"
        },
        'contract_manufacturer': {
            'class': 'form-control',  
            'placeholder': 'Enter contract manufacturer name here.',  # Add a placeholder
            "title": "Name of the contract manufacturer",
        },
        'test_site': {
            'class': 'form-control', 
            'placeholder': 'Enter test site path here.',  # Add a placeholder
            "title": "For ex: Zollner Germany",
        },
        'path_fail_level': {
            'class': 'form-control', 
            'placeholder': '/autofts/config/product/ps5000/data_levels.json',  # Add a placeholder
            "title": "/path/for/fail/level/",
        },
        'path_repair_list': {
            'class': 'form-control', 
            'placeholder': '/autofts/config/product/ps5000/data_lists.json',  # Add a placeholder
            "title": "/path/for/repair/list/",
        },
        'mrun_input': {
            'class': 'form-control', 
            'placeholder': '/common/maintDataSummaries',  # Add a placeholder
            "title": "Mrun Input contains the files created after the execution of a Smartest Activity",
        },
        'mod_count': {
            'class': 'form-control', 
            'placeholder': 'Enter mod counts here.',  # Add a placeholder
            "title": "Number of mods in hla",
        },
        'mod_channel_count': {
            'class': 'form-control', 
            'placeholder': 'Enter mode channel count here.', 
            "title": "Number of the channel per mod",
        },
        'has_fib': {
            'class': 'form-control',  
            'value': False,
            "title": "Does this HLA has FIB ?",
        },
        'has_bib': {
            'class': 'form-control',  
            'value': False,
            "title": "Does this HLA has BIB ?",
        },
        'has_pcon': {
            'class': 'form-control', 
            'value': False,
            "title": "Does this HLA has PCON ?",
        },
        'sys_cc_count': {
            'class': 'form-control',  # Add Bootstrap class to the input field
            'placeholder': 'Enter card cage count here',  # Add a placeholder
            "title": "Number of the Cart Cage for the product",
        },
        'sys_slot_count': {
            'class': 'form-control',  
            'placeholder': 'Enter Number of Slots here', 
            "title": "Number of slots for the product",
        },
    }

    def _get_form_args(self):
        form_args = {}
        for field_name, field in self.model.__table__.columns.items():
            if not field.nullable:  # Check if the field is required
                form_args[field_name] = {
                    "label": Markup(f"{field_name.replace('_', ' ').title()} <span style='color: red;'>*</span>")
                }
            else:
                form_args[field_name] = {
                    "label": field_name.replace('_', ' ').title()  # Default label for non-required fields
                }
        return form_args

    @property
    def form_args(self):
        return self._get_form_args()


    async def on_model_change(self, form, prod: schema.Product, is_created: bool, request: Request):
        # Validate the created_by field
        session: Session = self.session_maker()
        try:
            site_name = session.query(schema.Site).filter(schema.Site.id==form.get("site")).first().site_name
            if is_created:
                form["created_by"] = request.session.get("token")
                form["modified_by"] = request.session.get("token")
                form["site_name"] = site_name #form.get('site')
                del form['site']
            else:
                form["modified_by"] = request.session.get("token")
        except sqlite3.IntegrityError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The Product Name Already exists, Try with another name !",
                headers={"WWW-Authenticate": "Basic"},
            )


class FeAdmin(ModelView, model=schema.FileExplorerTab):
    column_list = [schema.FileExplorerTab.product,schema.FileExplorerTab.created_at,
                    schema.FileExplorerTab.label, schema.FileExplorerTab.path,
                    schema.FileExplorerTab.pattern, schema.FileExplorerTab.active ]
    form_columns = [schema.FileExplorerTab.product, schema.FileExplorerTab.label, schema.FileExplorerTab.path,
                    schema.FileExplorerTab.pattern, schema.FileExplorerTab.active]

    form_include_pk = True
    icon = "fa-solid fa-gears"


    def _get_form_args(self):
        form_args = {}
        for field_name, field in self.model.__table__.columns.items():
            if not field.nullable:  # Check if the field is required
                form_args[field_name] = {
                    "label": Markup(f"{field_name.replace('_', ' ').title()} <span style='color: red;'>*</span>")
                }
            else:
                form_args[field_name] = {
                    "label": field_name.replace('_', ' ').title()  # Default label for non-required fields
                }
        return form_args

    @property
    def form_args(self):
        return self._get_form_args()


    async def on_model_change(self, form, fe: schema.FileExplorerTab, is_created: bool, request: Request):
        session: Session = self.session_maker()
        prd = session.query(schema.Product).filter(schema.Product.id==form.get("product")).first().product_name
        if is_created:
            form["product_name"] = prd
            del form["product"]
        else:
            form["product_name"] = prd
            del form["product"]


class TestCellAdmin(ModelView, model = schema.TestCell):
    form_include_pk = True
    column_list = [schema.TestCell.product, schema.TestCell.created_at , schema.TestCell.host_name, schema.TestCell.test_cell, schema.TestCell.test_step ]
    form_columns = [schema.TestCell.product, schema.TestCell.host_name, schema.TestCell.test_cell, schema.TestCell.test_step ]
    icon = "fa-solid fa-gears"

    def _get_form_args(self):
        form_args = {}
        for field_name, field in self.model.__table__.columns.items():
            if not field.nullable:  # Check if the field is required
                form_args[field_name] = {
                    "label": Markup(f"{field_name.replace('_', ' ').title()} <span style='color: red;'>*</span>")
                }
            else:
                form_args[field_name] = {
                    "label": field_name.replace('_', ' ').title()  # Default label for non-required fields
                }
        return form_args

    @property
    def form_args(self):
        return self._get_form_args()


    async def on_model_change(self, form, testCell: schema.TestCell, is_created: bool, request: Request):
        session: Session = self.session_maker()
        prd = session.query(schema.Product).filter(schema.Product.id==form.get("product")).first().product_name
        if is_created:
            form["product_name"] = prd
            del form["product"]
        else:
            form["product_name"] = prd
            del form["product"]

class SiteAdmin(ModelView, model = schema.Site):
    form_include_pk = False
    column_list = [schema.Site.id, schema.Site.site_name]
    form_columns = [schema.Site.id, schema.Site.site_name]
    icon = "fa-solid fa-gears"


class TestPlanAdmin(ModelView, model=schema.TestPlan):
    form_include_pk = False
    column_list = [schema.TestPlan.product, schema.TestPlan.test_name, schema.TestPlan.sw_version, schema.TestPlan.is_enabled]
    form_columns = [schema.TestPlan.product, schema.TestPlan.test_name, schema.TestPlan.sw_version, schema.TestPlan.is_enabled]
    icon = "fa-solid fa-gears"

    def _get_form_args(self):
        form_args = {}
        for field_name, field in self.model.__table__.columns.items():
            if not field.nullable:  # Check if the field is required
                form_args[field_name] = {
                    "label": Markup(f"{field_name.replace('_', ' ').title()} <span style='color: red;'>*</span>")
                }
            else:
                form_args[field_name] = {
                    "label": field_name.replace('_', ' ').title()  # Default label for non-required fields
                }
        return form_args

    @property
    def form_args(self):
        return self._get_form_args()


    async def on_model_change(self, form, testplan: schema.TestPlan, is_created: bool, request: Request):
        session: Session = self.session_maker()
        prd = session.query(schema.Product).filter(schema.Product.id==form.get("product")).first().product_name
        if is_created:
            form["product_name"] = prd
            del form["product"]
        else:
            form["product_name"] = prd
            del form["product"]


admin.add_view(UserAdmin)
admin.add_view(SiteAdmin)
admin.add_view(ProductAdmin)
admin.add_view(FeAdmin)
admin.add_view(TestCellAdmin)
admin.add_view(TestPlanAdmin)


from json import dumps

@app.get("/products")
async def get_products(db: Session =  Depends(get_db)):
    try:
        all_products = db.query(schema.Product).all()
        return all_products
    except Exception as e:
        handle_db_errors(db, e)


@app.get("/products/{product_name}")
async def get_product(product_name: str, db: Session = Depends(get_db)):
    try:
        product = db.query(schema.Product).filter(schema.Product.product_name == product_name).first()
        if product is None:
            raise HTTPException(status_code=404, detail="Product not found")
        return product
    except Exception as e:
        handle_db_errors(db, e)



@app.get("/feConfigs")
async def get_FEconfigs(db: Session = Depends(get_db)):
    try:
        all_FE_configs = db.query(schema.FileExplorerTab).all()
        return all_FE_configs
    except Exception as e:
        handle_db_errors(db, e)



@app.get("/feConfigs/{product_name}")
async def get_FEconfig_by_product(product_name: str,db: Session = Depends(get_db)):
    try:
        fe_config = db.query(schema.FileExplorerTab).filter(schema.FileExplorerTab.product_name == product_name).first()
        return fe_config
    except Exception as e:
        handle_db_errors(db, e)



@app.get("/testConfigs")
async def get_testconfigs(db: Session = Depends(get_db)):
    try:
        all_test_configs = db.query(schema.TestCell).all()
        return all_test_configs
    except Exception as e:
        handle_db_errors(db, e)



@app.get("/testConfigs/{product_name}")
async def get_testconfigs_by_product(product_name: str, db: Session = Depends(get_db)):
    try:
        all_test_configs = db.query(schema.TestCell).filter(schema.TestCell.product_name == product_name).first()
        return all_test_configs
    except Exception as e:
        handle_db_errors(db, e)


@app.post("/process/file/testcell")
async def process_file_test_cell(file: UploadFile, db:Session =  Depends(get_db)):
    is_valid_file = is_file_type_csv(file)

    if not is_valid_file:
        logger.info(f"{file.filename} is invalid file type, require csv file type !")
        raise HTTPException(status_code=400, detail="Invalid file type: File must be a CSV.")

    contents = await file.read()
    csv_file = StringIO(contents.decode('utf-8'))
    reader = csv.DictReader(csv_file)

    errors, valid_rows = valid_model_rows(db, reader, TestCellModel)
    
    # If there are errors, raise a 400 Bad Request with the error details
    if errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    # Insert valid rows into the database
    data_inserted = insert_data(db, schema.TestCell, valid_rows)
    return data_inserted
