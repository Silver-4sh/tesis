from collections import namedtuple

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import View
from django.views.generic import CreateView, FormView, TemplateView

from .forms import CustomUserCreationForm, CustomAuthenticationForm, CustomPasswordResetForm, CustomSetPasswordForm, EmailForm, UserUpdateForm
from .mixins import AuthSecurityMixin, LogMixin, EmailMixin, ProfilePermissionMixin
from .models import CustomUser


# region AUTHENTICATION

# region USER CREATION
class UserCreationView(AuthSecurityMixin, UserPassesTestMixin, LogMixin, EmailMixin, CreateView):
    form_class = CustomUserCreationForm
    template_name = 'auth/auth_user_creation.html'
    success_url = reverse_lazy('home')

    def form_valid(self, form):
        user = form.save()

        self.log(
            user=user,
            event_type='VAL:REGISTRO',
            details={'msj': 'Creación de cuenta exitosa.'})

        try:
            user_group, created = Group.objects.get_or_create(name='user')
            user.groups.add(user_group)

            self.verification_email(user)
            self.log(
                user=user,
                event_type='VAL:VERIFICACION_ENVIADA',
                details={'msj': 'Correo de verificación enviado.'})

            messages.success(
                request=self.request,
                message="Registro exitoso. Revise su correo para verificar su cuenta.",
                extra_tags='success')

        except Exception as e:
            self.log(
                user=user,
                event_type='VAL:VERIFICAION_ERR',
                details={'error': 'SMTP_ERROR', 'exception': str(e)})

            messages.warning(
                request=self.request,
                message="Error enviando el email.",
                extra_tags='warning')

        return redirect(self.success_url)

    def form_invalid(self, form):
        storage = messages.get_messages(self.request)
        storage.used = True
        processed_errors = set()

        for field, errors in form.errors.items():
            for error in errors:
                err_str = str(error)

                if "existe" in err_str:
                    display_msg = "Credenciales inválidas."
                    event = 'VAL:VERIFICAION_ERR'
                elif "CAPTCHA" in err_str:
                    display_msg = "Fallo de seguridad Captcha."
                    event = 'SEC:UNUSUAL_ACT'
                else:
                    display_msg = err_str
                    event = 'VAL:VERIFICAION_ERR'

                if display_msg not in processed_errors:
                    self.log(
                        user=None,
                        event_type=event,
                        details={'error': error},
                        manual_username=self.request.POST.get('username')
                    )
                messages.error(self.request, display_msg, extra_tags='danger')

        return super().form_invalid(form)


# endregion USER CREATION

# region LOGIN
class UserLoginView(AuthSecurityMixin, LogMixin, LoginView):
    form_class = CustomAuthenticationForm
    template_name = 'auth/auth_login.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.request.user
        self.log(
            user=user,
            event_type='AUTH:INICIO',
            details={'msj': 'Inicio de sesión exitoso.'})

        messages.success(
            request=self.request,
            message=f"Bienvenido {user.username}.")

        return response

    def form_invalid(self, form):
        username_attempted = form.data.get('username', 'Anónimo')
        self.log(
            user=None,
            event_type='AUTH:INICIO_ERR',
            details={'msj': 'Credenciales inválidas.'},
            manual_username=username_attempted)

        messages.error(
            request=self.request,
            message="Credenciales inválidas.",
            extra_tags='danger')

        return super().form_invalid(form)


# endregion LOGIN

# region LOGOUT """Vista para cerrar la sesión del usuario con auditoría."""
class LogoutView(LoginRequiredMixin, LogMixin, View):
    login_url = 'home'

    def get(self, request):
        # 1. Auditoría: Registramos el evento antes de invalidar la sesión
        self.log(
            user=request.user,
            event_type='AUTH:CIERRE',
            details={'msj': 'Cierre de sesión exitoso.'})

        # 2. Proceso de cierre de sesión de Django
        logout(request)

        # 3. Feedback al usuario
        messages.success(
            request=request,
            message="Has cerrado sesión correctamente. ¡Hasta pronto!")

        # 4. Redirección
        return redirect('home')


# endregion LOGOUT

# endregion AUTHENTICATION

# region USER VERIFICATION

# region ACCOUNT VERIFICATION
class VerifyAccountView(AuthSecurityMixin, UserPassesTestMixin, LogMixin, View):
    def get(self, request, uidb64, token):
        user = self.help_get_user(uidb64)

        if not user or not default_token_generator.check_token(user, token):
            err = "Usuario no encontrado" if not user else "Token inválido o expirado"

            self.log(
                user=user,
                event_type='VAL:VERIFICAION_ERR',
                details={'error': err, 'token': token if token else None}
            )
            return render(request, 'emails/verification_complete.html',
                          context={
                              'validlink': False,
                              'verified_user': None,
                              'uidb64': uidb64,
                          })

        user.is_verified = True
        user.save(update_fields=['is_verified'])
        self.log(
            user=user,
            event_type='VAL:VERIFICACION',
            details={'msj': 'Verificación de cuenta exitosa.'})

        return render(request, 'emails/verification_complete.html', {
            'verified_user': user,
            'validlink': True
        })

    @staticmethod
    def help_get_user(uidb64):
        """Helper para decodificar y obtener al usuario de forma segura."""
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            return CustomUser.objects.filter(pk=uid).first()
        except (TypeError, ValueError, OverflowError):
            return None


# endregion ACCOUNT VERIFICATION

# region VERIFICATION RESEND
class ResendActivationView(EmailMixin, LogMixin, View):
    def get(self, request, uidb64_pk):
        user = VerifyAccountView.help_get_user(uidb64_pk)

        if not user:
            user = CustomUser.objects.filter(pk=uidb64_pk).first()

        if user and not user.account_verified:
            self.verification_email(user)
            self.log(
                user=user,
                event_type='VAL:VERIFICACION_ENVIADA',
                details={'msj': 'Email de verificación enviado.', 'reenviado': True})

            messages.success(request,
                             message="Se ha enviado un nuevo enlace de activación.",
                             extra_tags='success')
        else:
            self.log(
                user=user,
                event_type='VAL:VERIFICAION_ERR',
                details={'error': 'SMTP_ERROR'})

            messages.error(request=request,
                           message="No se pudo procesar la solicitud.",
                           extra_tags='danger')

        return redirect('home')


# endregion VERIFICATION RESEND

# endregion USER VERIFICATION

# region PASSWORD MANAGEMENT

# region PASSWORD RESET REQUEST
class UserPasswordResetView(LogMixin, PasswordResetView):
    """Vista para solicitar el restablecimiento de contraseña."""
    template_name = 'emails/pass_reset.html'
    html_email_template_name = 'emails/pass_reset_email.html'
    email_template_name = 'emails/pass_reset_email_plain.txt'
    subject_template_name = 'emails/pass_reset_subject.txt'
    success_url = reverse_lazy('pass-reset-done')
    form_class = CustomPasswordResetForm

    def form_valid(self, form):
        """Ejecutado cuando el formulario es válido y se procede a enviar el email."""
        email = form.cleaned_data.get('email')

        self.log(
            user=None,
            event_type='SEC:CONTRASEÑA_CAMBIO',
            details={'msj': f'Solicitud de restablecimiento', 'correo': email, },
            manual_username=email
        )

        return super().form_valid(form)


# endregion PASSWORD RESET REQUEST

# region PASSWORD RESET REQUEST DONE
class UserPasswordResetDoneView(PasswordResetDoneView):
    """Vista que confirma que el email ha sido enviado."""
    template_name = 'emails/pass_reset_done.html'


# endregion PASSWORD RESET REQUEST DONE

# region PASSWORD RESET SET
class UserPasswordResetConfirmView(LogMixin, PasswordResetConfirmView):
    """ Vista donde el usuario introduce su nueva contraseña """

    template_name = 'emails/pass_reset_confirm.html'
    form_class = CustomSetPasswordForm
    success_url = reverse_lazy('pass-reset-complete')

    def form_valid(self, form):
        # 1. Ejecutamos el guardado de la nueva contraseña
        response = super().form_valid(form)

        # 2. Auditoría y feedback
        self.log(
            user=form.user,
            event_type='SEC:CONTRASEÑA_CAMBIO',
            details={'msj': 'Contraseña cambiada.'}
        )

        return response

    def form_invalid(self, form):
        storage = messages.get_messages(self.request)
        storage.used = True

        for field, errors in form.errors.items():
            for error in errors:
                err_str = str(error)
                messages.error(self.request, f"{err_str}", extra_tags='danger')

        return super().form_invalid(form)


# endregion PASSWORD RESET SET

# region PASSWORD RESET COMPLETE
class UserPasswordResetCompleteView(PasswordResetCompleteView):
    """Vista que confirma que la contraseña se cambió con éxito."""
    template_name = 'emails/pass_reset_complete.html'


# endregion PASSWORD RESET COMPLETE

# endregion PASSWORD MANAGEMENT

# region EMAIL
class SendEmailView(EmailMixin, FormView):
    template_name = 'emails/send_email.html'
    form_class = EmailForm
    success_url = reverse_lazy('home')

    def get_initial(self):
        initial = super().get_initial()
        if self.request.user.is_authenticated:
            initial['username'] = self.request.user.username
            initial['email'] = self.request.user.email
        return initial

    def form_valid(self, form):
        # 1. Extraer datos del formulario (independientemente de si está logueado o no)
        form_username = form.cleaned_data.get('username')
        form_email = form.cleaned_data.get('email')
        subject = form.cleaned_data['subject']
        message = form.cleaned_data['message']

        # 2. Determinar quién envía
        if self.request.user.is_authenticated:
            user_data = self.request.user
        else:
            # Validamos manualmente que existan si no hay sesión
            if not form_username or not form_email:
                messages.error(
                    request=self.request,
                    message="Por favor, introduce tu nombre y correo.",
                    extra_tags='danger')
                return self.form_invalid(form)

            UserContact = namedtuple('UserContact', ['username', 'email'])
            user_data = UserContact(username=form_username, email=form_email)

        try:
            self.email(user_data, subject, message)
            messages.success(
                request=self.request,
                message="Tu mensaje ha sido enviado con éxito.",
                extra_tags='success')

        except Exception as e:
            messages.error(
                request=self.request,
                message="No se pudo enviar el mensaje. Revisa la configuración del servidor de correo.",
                extra_tags='danger')

        return super().form_valid(form)


# endregion EMAIL

# region PROFILE

# region PROFILE VIEW
class ProfileView(View):
    template_name = 'accounts/profile.html'

    @staticmethod
    def get_target_user(request):
        user_id = request.GET.get('id')
        if user_id:
            return get_object_or_404(CustomUser, id=user_id)
        return request.user

    def get(self, request):
        target_user = self.get_target_user(request)

        user_fields = ['email', 'name', 'ci', 'location', 'phone_number', 'entity_type']
        admin_fields = ['account_status', 'account_verified', 'role']

        def get_display_data(fields):
            data = []
            for field_name in fields:
                # 1. Try to get the label from the model field
                try:
                    label = CustomUser._meta.get_field(field_name).verbose_name.title()
                except:
                    # 2. Fallback for @property 'role' or other non-DB fields
                    label = field_name.replace('_', ' ').title()

                # 3. Get the value (works for both fields and @property)
                value = getattr(target_user, field_name)
                data.append({'label': label, 'value': value})
            return data

        context = {
            'profile_user': target_user,
            'user_data': get_display_data(user_fields),
            'admin_data': get_display_data(admin_fields),
        }
        return render(request, self.template_name, context)


# endregion PROFILE VIEW


# endregion PROFILE


class BaseErrorView(TemplateView):
    status_code = 400

    def dispatch(self, request, *args, **kwargs):
        return self.render_to_response(self.get_context_data(), status=self.status_code)


class Custom400View(BaseErrorView):
    template_name = 'errors/error_400.html'
    status_code = 400


class Custom403View(BaseErrorView):
    template_name = 'errors/error_403.html'
    status_code = 403


class Custom404View(BaseErrorView):
    template_name = 'errors/error_404.html'
    status_code = 404


def custom_500_handler(request):
    return render(request, 'errors/error_500.html', status=500)


class TestView(View):
    template_name = 'test.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        return render(request, self.template_name)


class HomeView(View):
    template_name = 'home.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        return render(request, self.template_name)
