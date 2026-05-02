# FORMS
import hashlib

from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.html import strip_tags
from django.utils.http import urlsafe_base64_encode
from django_ratelimit.decorators import ratelimit
from honeypot.decorators import check_honeypot

from EcoCircular import settings
from tesis.models import Logs


class FormStylesMixin:
    def apply_styles(self, captcha_action='form'):
        labels_map = {
            'username': "Nombre de usuario",
            'email': "Correo electrónico",
            'password': "Contraseña",
            'subject': "Asunto",
            'message': "Mensaje",
            'new_password1': "Nueva contraseña",
            'new_password2': "Repite la nueva contraseña",
        }

        placeholders_map = {
            'username': "Nombre de usuario",
            'email': "Correo electrónico",
            'password': "Contraseña",
            'subject': "Asunto",
            'message': "Mensaje",
            'ci': "Carnet de Identidad",
            'phone_number': "Teléfono",
        }

        for field_name, field in self.fields.items():
            if field_name != 'captcha':
                if field_name in labels_map:
                    field.label = labels_map[field_name]

                placeholder_text = placeholders_map.get(field_name, field.label)

                css_classes = 'form-control'
                if hasattr(self, 'errors') and field_name in self.errors:
                    css_classes += ' is-invalid'

                field.widget.attrs.update({
                    'class': css_classes,
                    'placeholder': placeholder_text
                })

        if 'captcha' in self.fields:
            captcha_field = self.fields.pop('captcha')
            self.fields['captcha'] = captcha_field


class AuthSecurityMixin(UserPassesTestMixin):
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


class LogMixin:
    """Registro de auditoría compatible con Railway (Proxy IP)."""

    def log(self, user, event_type, details=None, manual_username=None):
        meta = self.request.META

        x_forwarded_for = meta.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = meta.get('REMOTE_ADDR')

        # 2. Identifier Logic
        if user:
            name = user.username
        elif manual_username:
            name = manual_username
        else:
            name = "Anónimo"

        # 3. Session Fingerprinting (Anonymized)
        session_key = getattr(self.request.session, 'session_key', None)
        s_hash = hashlib.sha256(session_key.encode()).hexdigest() if session_key else None

        # 4. Metadata structuring (JSONField)
        if isinstance(details, dict):
            metadata_payload = details
        else:
            metadata_payload = {"message": str(details)} if details else {}

        # 5. Create Log Entry
        return Logs.objects.create(
            user=user,
            username=name,
            event_type=event_type,
            metadata=metadata_payload,
            ip_address=ip,
            proxy_info=meta.get('HTTP_VIA', meta.get('HTTP_FORWARDED', '')),
            accept_language=meta.get('HTTP_ACCEPT_LANGUAGE', '')[:50],
            session_hash=s_hash,
            user_agent=meta.get('HTTP_USER_AGENT', '<unknown>')
        )


class EmailMixin:
    """Encapsula la lógica de envío de correos de la aplicación."""

    def send_mail(self, subject, text_content, html_content, from_email, to_email, reply_to=None):
        recipient = [to_email] if to_email else [settings.EMAIL_HOST_USER]

        mail = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email,
            to=recipient,
            reply_to=reply_to
        )
        mail.attach_alternative(html_content, "text/html")
        mail.send(fail_silently=False)

    def verification_email(self, user):
        """Prepara las variables para el correo de activación."""
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
            'activation_url': getattr(settings, 'SITE_NAME', 'EcoCircular'),
        }

        subject = "Activa tu cuenta de EcoCircular"
        html_content = render_to_string('emails/verification_email.html', context)
        text_content = strip_tags(html_content)

        self.send_mail(
            subject=subject,
            text_content=text_content,
            html_content=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to_email=user.email
        )

    def email(self, user, subject, message, to_email=None):
        """Prepara las variables para el correo de contacto al administrador."""
        current_site = get_current_site(self.request)

        context = {
            'user': user,
            'subject': subject,
            'message': message,
            'domain': current_site.domain,
        }

        subject = f"[EcoCircular Soporte] {subject}"
        html_content = render_to_string('../templates/emails/contact_email.html', context)
        text_content = f"Mensaje de {user.username} ({user.email}):\n\n{message}"

        self.send_mail(subject, text_content, html_content, user.email, to_email, reply_to=[user.email])


class ProfilePermissionMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Handles the granular logic:"""

    def test_func(self):
        target_user = self.get_object()
        current_user = self.request.user

        if current_user.is_superuser:
            return True

        # Admins can access the edit view for anyone
        if current_user.role == 'admin':
            return True

        # Regular users can only access their own edit view
        if current_user.role == 'user':
            return target_user == current_user

        return False

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        user = self.request.user
        target = self.get_object()

        # Define your field sets
        user_fields = ['email', 'name', 'ci', 'location', 'phone_number', 'entity_type']
        admin_fields = ['account_status', 'account_verified', 'role']

        if user.role == 'admin' and user != target and not user.is_superuser:
            # Hide/Remove all User-specific fields
            for field in user_fields:
                if field in form.fields:
                    del form.fields[field]

        elif user.role == 'user' and user == target:
            # Hide/Remove all Admin-specific fields so they can't promote themselves
            for field in admin_fields:
                if field in form.fields:
                    del form.fields[field]

        return form
