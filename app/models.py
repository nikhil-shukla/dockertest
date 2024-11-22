from pydantic import BaseModel, Field, EmailStr, model_validator, constr, conint
from datetime import datetime
from typing import Optional
from enum import Enum
import schema

class Product(BaseModel):
    product_name: constr(min_length=1)
    path_fail_level: constr(min_length=1)
    path_repair_list: constr(min_length=1)
    mrun_input: constr(min_length=1)
    mod_count: conint(ge=1)
    mod_channel_count: conint(ge=1)
    has_fib: bool = False
    has_bib: bool = False
    has_pcon: bool = False
    sys_cc_count: conint(ge=1)
    sys_slot_count: conint(ge=1)
    created_at: Optional[datetime] = None  
    modified_at: Optional[datetime] = None 
    created_by: EmailStr
    modified_by: EmailStr
    site_name: constr(min_length=1)

    class Config:
        from_attributes = True 


class User(BaseModel):
    name: constr(min_length=1) 
    email: EmailStr
    is_admin: bool = False
    is_autoftsuser: bool = False
    is_superuser: bool = False


class FileExplorerTab(BaseModel):
    label: str
    active: bool = True
    path: constr(min_length=1)
    pattern: constr(min_length=1)
    product_name: constr(min_length=1)
    create_at: Optional[datetime] = Field(default_factory=datetime.now)

class TestSteps(str, Enum):
    PRETEST = "PRETEST"
    FTV = "FTV"    

    def __str__(self):
        print(self.value)
        return self.value    

    def __repr__(self):
        print(self.value, "val")
        return  f"TestSteps.{self.name}({self.value!r})" 


class TestCellModel(BaseModel):
    id: Optional[int]  = None
    host_name: constr(min_length=1)
    test_step: TestSteps = TestSteps.PRETEST
    test_cell: constr(min_length=1)
    product_name: constr(min_length=1)
    created_at: Optional[datetime] = None  

    class Config:
        from_attributes = True

    @model_validator(mode='before')
    def check_product_name_exists(cls, v, info):
        # Assuming you have access to the DB session here
        db_session = v.get("context").get('db_session')  # Assuming session is passed to Pydantic model
        Product = v.get("product_name")
        if not db_session.query(schema.Product).filter(schema.Product.product_name == Product).first():
            raise ValueError(f"Product with product_name '{v}' does not exist.")
        del v["context"]
        return v
