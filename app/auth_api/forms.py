from flask_wtf import FlaskForm

from flask_wtf.file import FileField, FileRequired, DataRequired

from wtforms import (DateField, TextField,
                     SubmitField, SelectField, TextAreaField,
                     BooleanField, PasswordField)

from wtforms import validators


# Create form for User Registration
class RegistrationForm(FlaskForm):
    username = TextField('Username', [validators.Length(min=4, max=20)])
    email = TextField('Email Address', [validators.Length(min=6, max=50)])
    password = PasswordField('New Password', [
                             validators.DataRequired(),
                             validators.EqualTo('confirm',
                                                message='Passwords must match')
                             ])

    picture = FileField('Image', validators=[
        FileRequired()
    ])

    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the Terms of Service and \
                              Privacy Notice (updated Jul 31, 2017)',
                              [validators.DataRequired()])

    submit = SubmitField("Register")


# Create form for CRUD operations
class CreateForm(FlaskForm):
    name = TextField("Name", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    image = FileField('Image', validators=[
        FileRequired()
    ])
    banner = FileField('Image', validators=[
        FileRequired()
    ])
    youtubeVideoURL = TextField("Trailer on Youtube",
                                validators=[DataRequired()])

    category = SelectField('Genre',
                           choices=[('1', 'Action'),
                                    ('2', 'Action-Adventure'),
                                    ('3', 'Adventure'),
                                    ('4', 'Role-playing'),
                                    ('5', 'Simulation'),
                                    ('6', 'Sports'),
                                    ('7', 'Strategy')])

    platform = SelectField('Platform',
                           choices=[('Playstation', 'Playstation'),
                                    ('XBox', 'XBox'),
                                    ('PC', 'PC')])

    creators = TextField('Creators', validators=[DataRequired()])

    release_date = DateField('Release Date', format='%m/%d/%Y')

    submit = SubmitField("Create")
