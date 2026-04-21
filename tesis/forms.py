from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, SetPasswordForm, PasswordResetForm
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

        self.fields['username'].label = "Nombre de usuario"
        self.fields['email'].label = "Correo"

        for field_name, field in self.fields.items():
            if field_name != 'captcha':
                field.widget.attrs.update({'class': 'form-control',
                                           'placeholder': field.label
                                           })

        captcha_field = self.fields.pop('captcha')
        self.fields['captcha'] = captcha_field


# accounts/forms.py

class CustomAuthenticationForm(AuthenticationForm):
    captcha = ReCaptchaField(widget=ReCaptchaV3())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'].label = "Nombre de usuario"
        self.fields['password'].label = "Contraseña"

        for field_name, field in self.fields.items():
            css_classes = 'form-control'
            if field_name in self.errors:
                css_classes += ' is-invalid'

            field.widget.attrs.update({
                'class': css_classes,
                'placeholder': field.label
            })

    def clean(self):
        # 2. Forzamos la limpieza del error de captcha si existe
        cleaned_data = super().clean()
        if 'captcha' in self._errors:
            del self._errors['captcha']
        return cleaned_data


class CustomPasswordResetForm(PasswordResetForm):
    """Formulario de recuperación de contraseña con estilos personalizados."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['email'].label = "Correo"

        for field_name, field in self.fields.items():
            css_classes = 'form-control'
            if field_name in self.errors:
                css_classes += ' is-invalid'

            field.widget.attrs.update({
                'class': css_classes,
                'placeholder': field.label
            })


class CustomSetPasswordForm(SetPasswordForm):
    """Formulario personalizado para establecer la nueva contraseña."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'form-control bg-transparent text-white border-light border-opacity-25',
            })

            if field_name == 'new_password1':
                field.widget.attrs.update({'placeholder': 'Nueva contraseña'})
            elif field_name == 'new_password2':
                field.widget.attrs.update({'placeholder': 'Repite la nueva contraseña'})
