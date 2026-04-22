from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views import View
from django.views.generic import CreateView
from django_ratelimit.decorators import ratelimit
from honeypot.decorators import check_honeypot

from EcoCircular import settings
from .forms import CustomUserCreationForm, CustomAuthenticationForm, CustomPasswordResetForm, CustomSetPasswordForm
from .models import CustomUser, AuthLogs


# --- MIXINS DE INFRAESTRUCTURA ---
class AuthSecurityMixin:
    """Encapsula la seguridad para vistas de autenticación."""

    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    @method_decorator(ratelimit(key='post:username', rate='5/m', method='POST', block=True))
    @method_decorator(check_honeypot(field_name='full_name_field'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def test_func(self):
        """
        Medida de seguridad: Solo permite el acceso si el usuario NO está autenticado.
        Si ya está logueado, dispara el redireccionamiento.
        """
        return not self.request.user.is_authenticated

    def handle_no_permission(self):
        """Si el usuario ya está autenticado y trata de entrar al login, va al home."""
        return redirect('home')


class AuthLogMixin:
    """Registro de auditoría compatible con Railway (Proxy IP)."""

    def auth_log(self, user, event_type, details="", manual_username=None):
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0] if x_forwarded_for else self.request.META.get('REMOTE_ADDR')
        user_agent = self.request.META.get('HTTP_USER_AGENT', '<unknown>')

        if user:
            name = user.username
        elif manual_username:
            name = manual_username
        else:
            name = "Anónimo"

        AuthLogs.objects.create(
            user=user,
            username=name,
            event_type=event_type,
            details=details,
            ip_address=ip,
            user_agent=user_agent
        )


class AuthEmailMixin:
    """Encapsula los datos del correo para vistas de autenticación."""

    def auth_mail(self, user):
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        current_site = get_current_site(self.request)
        protocol = 'https' if self.request.is_secure() else 'http'
        activation_url = f"{protocol}://{current_site.domain}/activate/{uid}/{token}/"
        context = {
            'user': user,
            'domain': current_site.domain,
            'uid': uid,
            'token': token,
            'protocol': protocol,
            'activation_url': activation_url,
        }

        html_content = render_to_string('accounts/verification_email.html', context)
        text_content = f"Hola {user.username}, activa tu cuenta aquí: {activation_url}"

        # Configuración del objeto de correo
        mail = EmailMultiAlternatives(
            subject="Activa tu cuenta de EcoCircular",
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )

        mail.attach_alternative(html_content, "text/html")
        mail.send(fail_silently=False)


# --- VISTAS ---

class UserCreationView(AuthSecurityMixin, UserPassesTestMixin, AuthLogMixin, AuthEmailMixin, CreateView):
    form_class = CustomUserCreationForm
    template_name = 'auth/auth_user_creation.html'
    success_url = reverse_lazy('home')

    def form_valid(self, form):
        user = form.save(commit=False)
        user.is_active = False
        user.save()

        self.auth_log(user, 'Registro', 'Registro inicial exitoso.')

        try:
            self.auth_mail(user)
            self.auth_log(user, 'Verificación', 'Email de activación enviado.')
            messages.success(self.request, "Registro exitoso. Revisa tu email para verificar tu cuenta.")
        except Exception as e:
            self.auth_log(user, 'Verificación', f'Error SMTP: {str(e)}')
            messages.warning(self.request, "Error enviando el email.")

        return redirect(self.success_url)

    def form_invalid(self, form):
        username_attempted = form.data.get('username', 'Anónimo')
        storage = messages.get_messages(self.request)
        storage.used = True
        showed_error = False

        for field, errors in form.errors.items():
            for error in errors:
                err_str = str(error)

                if "existe" in err_str:
                    if not showed_error:
                        self.auth_log(None, 'Registro', 'Credenciales inválidas.', manual_username=username_attempted)
                        messages.error(self.request, "Credenciales inválidas.", extra_tags='danger')
                        showed_error = True
                elif "CAPTCHA" in err_str and not showed_error:
                    self.auth_log(None, 'Registro', 'Fallo de seguridad Captcha.', manual_username=username_attempted)
                    messages.error(self.request, "Fallo de seguridad Captcha.", extra_tags='danger')
                else:
                    self.auth_log(None, 'Registro', err_str, manual_username=username_attempted)
                    messages.error(self.request, err_str, extra_tags='danger')
        return super().form_invalid(form)


class UserLoginView(AuthSecurityMixin, UserPassesTestMixin, AuthLogMixin, LoginView):
    """Vista de Login utilizando CBV y Mixins de auditoría."""
    form_class = CustomAuthenticationForm
    template_name = 'auth/auth_login.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        self.auth_log(self.request.user, 'login', 'Inicio de sesión exitoso.')
        messages.success(self.request, f"Bienvenido {self.request.user.username}.")
        return response

    def form_invalid(self, form):
        username_attempted = form.data.get('username', 'Anónimo')
        self.auth_log(None, 'login', 'Credenciales inválidas.', manual_username=username_attempted)
        messages.error(self.request, "Credenciales inválidas.", extra_tags='danger')
        return super().form_invalid(form)


class LogoutView(LoginRequiredMixin, AuthLogMixin, View):
    login_url = 'home'

    def get(self, request):
        self.auth_log(request.user, 'Cierre de sesión', 'Cierre de sesión.')
        logout(request)
        messages.success(request, "Sesión cerrada.")
        return redirect('home')


class VerifyAccountView(AuthSecurityMixin, UserPassesTestMixin, AuthLogMixin, View):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except:
            user = None

        if user and default_token_generator.check_token(user, token):
            user.is_active = True
            user.account_verified = True
            user.account_status = 'active'
            user.save(update_fields=['is_active', 'account_verified', 'account_status'])

            self.auth_log(user, 'Verificación', 'Cuenta verificada exitosamente.')
            return render(request, 'accounts/verification_success.html', {'verified_user': user})

        self.auth_log(user, 'Verificación', 'Fallo en verificación (Token inválido).')
        messages.error(request, "Fallo en verificación (Token inválido).", extra_tags='danger')
        return redirect('home')


class UserPasswordResetView(PasswordResetView):
    """Vista para solicitar el restablecimiento de contraseña."""
    template_name = 'auth/pass_reset.html'  # El formulario en la web
    html_email_template_name = 'auth/pass_reset_email.html'
    email_template_name = 'auth/pass_reset_email_plain.txt'
    subject_template_name = 'auth/pass_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')
    form_class = CustomPasswordResetForm


class UserPasswordResetDoneView(PasswordResetDoneView):
    """Vista que confirma que el email ha sido enviado."""
    template_name = 'auth/pass_reset_done.html'


# views.py - Proyecto EcoCircular

# views.py - Proyecto EcoCircular

# views.py - Proyecto EcoCircular

class UserPasswordResetConfirmView(AuthLogMixin, PasswordResetConfirmView):
    """
    Vista donde el usuario introduce su nueva contraseña.
    Proporciona feedback detallado de errores y registro de auditoría.
    """
    template_name = 'auth/pass_reset_confirm.html'
    form_class = CustomSetPasswordForm
    success_url = reverse_lazy('password_reset_complete')

    def form_valid(self, form):
        response = super().form_valid(form)

        uidb64 = self.kwargs.get('uidb64')
        user = self.get_user(uidb64)  # Ahora con el argumento requerido
        user.refresh_from_db()

        return response

    def form_invalid(self, form):
        storage = messages.get_messages(self.request)
        storage.used = True

        for field, errors in form.errors.items():
            for error in errors:
                err_str = str(error)
                messages.error(self.request, f"{err_str}", extra_tags='danger')

        return super().form_invalid(form)


class UserPasswordResetCompleteView(PasswordResetCompleteView):
    """Vista que confirma que la contraseña se cambió con éxito."""
    template_name = 'auth/pass_reset_complete.html'


class ProfileView(View):
    template_name = 'accounts/profile.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        return render(request, self.template_name)


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
