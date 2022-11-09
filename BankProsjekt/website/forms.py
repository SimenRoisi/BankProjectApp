from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, equal_to, Email, DataRequired, ValidationError, Required
from .models import User


class RegisterForm(FlaskForm):
    def validate_email(self, email_to_check):
        email_address = User.query.filter_by(email_address=email_to_check).first()
        if email_address:
            return False
        else:
            return True

    email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    first_name = StringField(label="Enter first name:", validators=[Length(min=1), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[equal_to('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')


class LoginForm(FlaskForm):
    email_address = StringField(label='Enter email:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign in')
    token = StringField('Token', validators=[DataRequired(), Length(6, 6)])
