import sqlite3
import sys
from main import hash_password

try:
    # define users
    users = [
        f"(1,'vishal@siemens.com','vishal', '{str(hash_password('vishal'))}', 1, 1, 1)",
        f"(2,'yeray@advantest.com','yeray', '{str(hash_password('yeray'))}', 1, 1, 1)",
    ]
    # create users
    connection =  sqlite3.connect("test.db")
    cursor = connection.cursor()
    for i,user in enumerate(users):
        print(i,user)
        sql = f"Insert into users (id, email, username, password, is_admin, is_autoftsuser, is_superuser) values {user}"
        print(i,sql)
        cursor.execute(sql)
    # dump all users
    print(cursor.execute("Select * from users").fetchall())
    connection.commit()
except Exception as e:
    print("Error Occured While creating the super user: \n", e)

finally:
    print('---')
    print('---finally')
    users = cursor.execute("Select * from users").fetchall()
    for i,user in enumerate(users):
        print(i,user)
    cursor.close()
    connection.close()
