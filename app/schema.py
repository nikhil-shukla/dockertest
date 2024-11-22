from sqlalchemy import Column, Integer, String, TIMESTAMP, ForeignKey, Boolean, func, Enum, LargeBinary
from database import Base
from sqlalchemy.orm import relationship
import enum


class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    is_autoftsuser = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)

    # Relationships
    created_products = relationship("Product", back_populates="creator", foreign_keys="Product.created_by")
    modified_products = relationship("Product", back_populates="modifier", foreign_keys="Product.modified_by")

    def __repr__(self):
        return self.email


class Site(Base):
    __tablename__ = "site"
    id = Column(Integer, primary_key=True, index=True)
    site_name = Column(String, unique=True, nullable=False)
    product =  relationship("Product", back_populates="site")
    
    # product_name = Column(String, ForeignKey('product.product_name'), nullable=False)
    # product = relationship("Product", back_populates="site", foreign_keys=[product_name])

    def __repr__(self):
        return f"{self.site_name}"


class Product(Base):
    __tablename__ = "product"
    id = Column(Integer, primary_key=True, index=True)
    product_name = Column(String, unique=True, nullable=False)
    path_fail_level = Column(String,  nullable=False)
    path_repair_list = Column(String,  nullable=False)
    mrun_input = Column(String,  nullable=False)
    mod_count = Column(Integer,  nullable=False)
    mod_channel_count = Column(Integer,  nullable=False)
    has_fib = Column(Boolean, default=False)
    has_bib = Column(Boolean, default=False)
    has_pcon = Column(Boolean, default=False)
    sys_cc_count = Column(Integer,  nullable=False)
    sys_slot_count = Column(Integer,  nullable=False)

    created_at = Column(TIMESTAMP, server_default=func.now())
    modified_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    created_by = Column(String, ForeignKey('users.email'), nullable=False)
    modified_by = Column(String, ForeignKey('users.email'), nullable=False)
    site_name = Column(String, ForeignKey('site.site_name'), nullable=False)
    # DELETING
    # contract_manufacturer = Column(String,  nullable=False)
    # test_site = Column(String,  nullable=True)

    # Relationships

    site = relationship("Site", back_populates="product", foreign_keys=[site_name])
    file_explorer_tabs = relationship("FileExplorerTab", back_populates="product")
    creator = relationship("User", back_populates="created_products", foreign_keys=[created_by])
    modifier = relationship("User", back_populates="modified_products", foreign_keys=[modified_by])
    test_cell =  relationship("TestCell", back_populates="product")
    test_plan_name =  relationship("TestPlan", back_populates="product")

    class Config:
        orm_mode = True

    def __repr__(self):
        return self.product_name


class FileExplorerTab(Base):
    __tablename__ = 'file_explorer_tabs'
    
    id = Column(Integer, primary_key=True)
    label = Column(String, nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    path = Column(String,  nullable=False)
    pattern = Column(String,  nullable=False)
    product_name = Column(String, ForeignKey('product.product_name'), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    

    product = relationship("Product", back_populates="file_explorer_tabs", foreign_keys=[product_name])

    def __repr__(self):
        #return f"({self.label}, {self.product_name})"
        return f"{self.label}"
    

class TestSteps(enum.Enum):
    PRETEST = "PRETEST"
    FTV = "FTV"

    def __str__(self):
        return self.value    

    def __repr__(self):
        print(self.value, "val")
        return  f"TestSteps.{self.name}({self.value!r})" 


class TestCell(Base):
    __tablename__ = "test_cell"
    id = Column(Integer, primary_key=True)
    host_name =  Column(String, nullable=False)
    test_cell =  Column(String, nullable=False)
    test_step =  Column(Enum(TestSteps), default=TestSteps.PRETEST, nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())

    product_name = Column(String, ForeignKey('product.product_name'), nullable=False)
    product = relationship("Product", back_populates="test_cell", foreign_keys=[product_name])

    class Config:
        orm_mode = True

    def __str__(self):
        return str(self.test_cell)
    
    def __repr__(self):
        return f"TestCell(test_cell={self.test_cell})"


class FileStore(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True)
    file = Column(LargeBinary)


class TestPlan(Base):
    __tablename__ = "test_plans"
    id = Column(Integer, primary_key=True)
    sw_version = Column(String, nullable=False)
    test_name = Column(String, nullable=False)
    is_enabled = Column(Boolean, default=True)
    product_name = Column(String, ForeignKey('product.product_name'), nullable=False)
    product = relationship("Product", back_populates="test_plan_name", foreign_keys=[product_name])
  
    class Config:
        orm_mode = True

    def __str__(self):
        return str(self.test_name)
    
    def __repr__(self):
        return f"Testplan(test_plan={self.test_name})"


