# Space App 
-----------------------
This is simple app used by all space companies such as (Nasa and spaceX) to share their latest acheivment. This app programmed using python and flask framework.

## Requirments
python version 3 ( Can be download from [here](https://www.python.org/downloads/))

virtual Environment.

## DataBase
DataBase ( named **space** ) includes two tables:
* **Company** table includes information about the company 
 ```
 id (type: integer) Primary Key
 name (type: text) not null
 email (type: text) not null
 picture (type: text)
 ```

* **Acheivment** table includes all acheivments
 ```
 id (type: integer) Primary Key
 title (type: text) not null
 description (type: text) not null
 company_id (type: integer) Foregin key =>(Company.id)
 ```

## Installation
download or Clone the GitHub repository

https://github.com/Basheer88/spaceapp.git

# Files of the repository
database_setup : to generate an empty database run ( python database_setup)

initial_info : this will add one entry for the empty database. can be used to help you understand how to add entry to the database. run ( python initial_info.py)

SpaceApp file : this file to make the app working. first run (run python SpaceApp.py) then access the app using (localhost:8000)


# License
Free license. Feel free to do whatever you want with it.