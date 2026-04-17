# tesis/views.py
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.tokens import default_token_generator
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
# Importamos tu formulario con reCAPTCHA v3 y el orden corregido
from .forms import CustomUserCreationForm
from .models import CustomUser

User = CustomUser


class HomeView(View):
    template_name = 'home.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        return render(request, self.template_name)


@method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True), name='dispatch')
@method_decorator(ratelimit(key='post:username', rate='5/m', method='POST', block=True), name='dispatch')
@method_decorator(check_honeypot(field_name='full_name_field'), name='dispatch')
class UserCreationView(UserPassesTestMixin, CreateView):
    form_class = CustomUserCreationForm
    template_name = 'auth/auth_user_creation.html'
    success_url = reverse_lazy('home')

    def test_func(self):
        return not self.request.user.is_authenticated

    def handle_no_permission(self):
        return redirect('home')

    def form_valid(self, form):
        user = form.save(commit=False)
        user.is_active = False
        user.account_verified = False
        user.account_status = 'blocked'
        user.save()
        user.refresh_from_db()

        try:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            current_site = get_current_site(self.request)
            protocol = 'https' if self.request.is_secure() else 'http'
            context = {
                'user': user,
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
                'protocol': protocol,
            }

            activation_url = f"{protocol}://{current_site.domain}/activate/{uid}/{token}/"
            plain_message = f"Hola {user.username}, activa tu cuenta en: {activation_url}"
            html_message = render_to_string('accounts/verification_email.html', {
                **context, 'activation_url': activation_url
            })

            mail = EmailMultiAlternatives(
                subject="Activa tu cuenta de EcoCircular",
                body=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )
            mail.attach_alternative(html_message, "text/html")
            mail.send(fail_silently=False)
            messages.success(self.request, "Registro exitoso. Revisa tu email para activar tu cuenta.", extra_tags='success')
        except Exception as e:
            print(f"CRITICAL SMTP ERROR: {str(e)}")
            messages.warning(self.request, "Cuenta creada, pero hubo un error enviando el correo de activación. Contacte con Soporte")

        return redirect(self.success_url)

    def form_invalid(self, form):
        storage = messages.get_messages(self.request)
        storage.used = True

        showed_error = False

        for field, errors in form.errors.items():
            for error in errors:
                err_str = str(error).lower()

                if "obligatorio" in err_str:
                    continue

                if "existe" in err_str:
                    if not showed_error:
                        messages.error(self.request, "Credenciales inválidas.", extra_tags='danger')
                        showed_error = True
                else:
                    messages.error(self.request, str(error), extra_tags='danger')

        return super().form_invalid(form)


class LoginView(View):
    template_name = 'auth/auth_login.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        return render(request, self.template_name)


# region Logout
class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('home')


# endregion Logout


class VerifyAccountView(UserPassesTestMixin, View):
    def test_func(self):
        # Solo permite el acceso si el usuario NO está autenticado
        return not self.request.user.is_authenticated

    def handle_no_permission(self):
        # Si ya está autenticado, lo redirige al inicio
        messages.info(self.request, "Ya has iniciado sesión. No necesitas verificar otra cuenta.")
        return redirect('home')

    def get(self, request, uidb64, token):
        try:
            # Decodificación del ID del usuario
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None

        # 1. Validación de existencia
        if user is None:
            messages.error(request, "El enlace de activación es inválido o el usuario no existe.")
            return redirect('home')

        # 2. Validación de cuenta ya verificada
        if user.account_verified:
            messages.info(request, "Esta cuenta ya ha sido verificada anteriormente.")
            return render(request, 'accounts/verification_success.html', {'verified_user': user})

        # 3. Validación del Token y persistencia
        print("token check in VerifyAccountView = ", default_token_generator.check_token(user, token))
        if default_token_generator.check_token(user, token):
            # Actualización de estados
            user.is_active = True
            user.account_verified = True
            user.account_status = 'active'

            # Forzamos el guardado especificando los campos para evitar efectos secundarios
            user.save(update_fields=['is_active', 'account_verified', 'account_status'])

            messages.success(request, "¡Cuenta verificada con éxito! Ya puedes acceder.")
            return render(request, 'accounts/verification_success.html', {'verified_user': user})
        else:
            # Si llega aquí, el token expiró o es inválido
            messages.error(request, "El token de activación ha expirado o es incorrecto.")
            return redirect('home')
