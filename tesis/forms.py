from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, SetPasswordForm, PasswordResetForm
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV3

from .mixins import FormStylesMixin
from .models import CustomUser


class CustomUserCreationForm(UserCreationForm, FormStylesMixin):
    email = forms.EmailField(required=True)
    captcha = ReCaptchaField(widget=ReCaptchaV3())

    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('username', 'email')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.apply_styles(captcha_action='registration')


class CustomAuthenticationForm(AuthenticationForm, FormStylesMixin):
    captcha = ReCaptchaField(widget=ReCaptchaV3(attrs={'data-action': 'login'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.apply_styles(captcha_action='login')


class CustomPasswordResetForm(PasswordResetForm, FormStylesMixin):
    """Formulario de recuperación de contraseña con estilos personalizados."""

    captcha = ReCaptchaField(widget=ReCaptchaV3(attrs={'data-action': 'password_reset'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.apply_styles(captcha_action='password_reset')

        if 'email' in self.fields:
            self.fields['email'].widget.attrs.update({
                'placeholder': 'usuario@ejemplo.com',
                'class': 'form-control'
            })


class CustomSetPasswordForm(SetPasswordForm, FormStylesMixin):
    """Formulario personalizado para establecer la nueva contraseña."""

    captcha = ReCaptchaField(widget=ReCaptchaV3(attrs={'data-action': 'set_password'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.apply_styles(captcha_action='set_password')


class EmailForm(forms.Form, FormStylesMixin):
    username = forms.CharField(max_length=150, required=True)
    email = forms.EmailField(required=True)
    subject = forms.CharField(max_length=100, required=True)
    message = forms.CharField(widget=forms.Textarea(attrs={'rows': 5}), required=True)
    captcha = ReCaptchaField(widget=ReCaptchaV3(attrs={'data-action': 'contact'}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.apply_styles()


class UserUpdateForm(forms.ModelForm, FormStylesMixin):
    pass


class AdminUpdateForm(forms.ModelForm, FormStylesMixin):
    pass
