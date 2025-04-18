I. Quick Summary

This is a Python application built using Flask that manages four types of user accounts — Administrator, Inspector, Teacher, and Student/Parent—enabling permissions, comment-posting, and account maintenance.


II. Motivation

The motivation for developing this application is to provide a secure and organized platform for managing interactions between students, teachers, and the administrative staff. This application aims to:
1) Ensure Data Security: By controlling access and visibility of sensitive information, such as comments and account details.
2) Streamline Communication: Facilitate structured communication between teachers and students or parents, with the administrator overseeing and managing the process.
3)Enhance Accountability: Provide a transparent system where the administrator can monitor and manage interactions, ensuring that all communications are appropriate and helpful.


III. User Accounts and Password Management:
1) All users (students, teachers, and the administrator, inspectors) can change their passwords.
2) The administrator can create and delete student and teacher accounts, and change their passwords.
3) The inspector can see everything but has no editing rights (except own password)

IV. Role-Specific Features:

Administrator

1) Create and delete Teacher and Student/Parent accounts.
2) Change any user’s password.
3) Grant and revoke access to Teachers to comment on specific students.
4) View all student accounts and all comments posted by teachers.
5) View teacher accounts and see each teacher’s assigned students.

Teacher

1) Post comments on assigned student accounts (only to those allowed by the administrator). One teacher cannot see other teachers’ comments.
Viewing Comments: allowed only to the administrator(s), inspector(s) and the respective students' parents.



V. Usage
1) Create the Administrator and Database: python create_admin.py
2) Start the Flask Application: python app.py
3) Log In as Administrator and change administrator password: navigate to the "Change Password" section and follow the prompts.
4) Add user accounts (teachers, students) then grant access to teachers to their particular students. May add some fellow administrators.


VI. Dependencies: 
blinker==1.8.2,
click==8.1.7,
colorama==0.4.6,
Flask==3.0.3,
Flask-Login==0.6.3,
Flask-SQLAlchemy==3.1.1,
Flask-WTF==1.2.1,
greenlet==3.1.1,
itsdangerous==2.2.0,
Jinja2==3.1.4,
MarkupSafe==2.1.5,
SQLAlchemy==2.0.35,
typing_extensions==4.12.2,
Werkzeug==3.0.3,
WTForms==3.1.2 .
