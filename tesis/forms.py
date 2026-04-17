from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV3

from .models import CustomUser


class CustomUserCreationForm(UserCreationForm):
    captcha = ReCaptchaField(widget=ReCaptchaV3())

    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('username', 'email')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field_name, field in self.fields.items():
            if field_name != 'captcha':
                field.widget.attrs.update({'class': 'form-control'})

        captcha_field = self.fields.pop('captcha')
        self.fields['captcha'] = captcha_field


class CustomAuthenticationForm(AuthenticationForm):
    """Formulario de inicio de sesión con estilos Bootstrap 5 y reCAPTCHA v3."""
    captcha = ReCaptchaField(widget=ReCaptchaV3())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Inyectar clases de Bootstrap 5 a los campos de texto
        for field_name, field in self.fields.items():
            if field_name != 'captcha':
                field.widget.attrs.update({
                    'class': 'form-control',
                    'placeholder': field.label
                })
