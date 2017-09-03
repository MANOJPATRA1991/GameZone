# Item Catalog Project

This is the second project of Part 3, Core Curriculum, [Full Stack Web Developer Nanodegree Program](https://in.udacity.com/course/full-stack-web-developer-nanodegree--nd004/). 

This web application is live on [GameZone](https://gamezonev2.herokuapp.com/).

This project demonstrates my skills in developing a REST API server for a Flask web application.

## Table of Contents

  1. [Description](#description)
  2. [Installation and Test Requirements](#installation)
  3. [References](#references)
  4. [License](#license)
  
### Description

This project titled GameZone displays games for certain pre-defined categories to a user. 
If the user is logged in, he/she can create new game data and edit their own data if needed.
The app also has a user who acts as an admin with full access to perform CRUD operations on the database for improvement.
  
### Installation and Test Requirements

  1. To run this project in local environment, clone it with `git clone <URL>`.
  
  2. Run your vagrant machine with `vagrant up` and then `vagrant ssh`.
  
  3. Once done, open the project in your favorite IDE and install the dependencies mentioned in **requirements.txt** using `sudo pip install <module>` in your vagrant environment.
  
  4. **cd** into the project directory.
  
  3. Create the database with `python database_setup.py`
  
  4. Populate the database with categories and admin user by `python categories.py` and `python demo_user.py`.
  
  5. To run the application in your local environment, the command is `python run.py`.
  
  6. Once the server is up and running go to `http://localhost:8000` from your browser to view the app.

### References
1. [Python Documentation](https://docs.python.org/3/)
2. [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
3. [PEP8](https://www.python.org/dev/peps/pep-0008/)
4. [Flask](http://flask.pocoo.org/)
5. [SQLAlchemy](https://www.sqlalchemy.org/)

### License
The content of this repository is licensed under [MIT](https://choosealicense.com/licenses/mit/).
