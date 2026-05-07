from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, Group, AbstractUser
from django.core.validators import RegexValidator
from django.db import models

from EcoCircular import settings


class CustomUser(AbstractUser, PermissionsMixin):
    ENTITY_CHOICES = [
        ('tcp', 'Trabajador por Cuenta Propia'),
        ('organization', 'Organización/Empresa'),
    ]

    phone_validator = RegexValidator(
        regex=r'^5\d{7}$',
        message="El número debe ser un móvil (5...)."
    )

    # --- THE ROLE PROPERTY ---
    @property
    def role(self):
        if self.is_superuser:
            return 'superuser'
        if self.groups.filter(name='admin').exists():
            return 'admin'
        return 'user'

    email = models.EmailField(unique=True, max_length=255, verbose_name="Correo Electrónico",
                              error_messages={
                                  'unique': "Ya existe un usuario con este correo electrónico.",
                              }
                              )
    ci = models.CharField(
        max_length=11, unique=True, null=True,
        validators=[RegexValidator(r'^\d{11}$', 'CI must be 11 digits')],
        verbose_name="Carnet de Identidad"
    )
    phone_number = models.CharField(
        max_length=8, null=True, unique=True,
        validators=[phone_validator], verbose_name="Teléfono"
    )
    location = models.CharField(max_length=75, verbose_name="Dirección")
    entity_type = models.CharField(max_length=15, choices=ENTITY_CHOICES, verbose_name="Tipo de Entidad")
    is_verified = models.BooleanField(default=False, verbose_name="Verificado")

    USERNAME_FIELD = 'username'  # This tells Django which field to use for login
    REQUIRED_FIELDS = ['email']  # Fields prompted when running 'createsuperuser'

    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
        permissions = [
            ("can_change_admin_data", "Puede editar campos de administrador"),
            ("can_change_other_data", "Puede editar datos de otros usuarios"),
        ]

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def __str__(self):
        full_name = self.get_full_name()
        return f"{self.username} ({full_name})" if full_name else self.username


class Logs(models.Model):
    EVENT_CHOICES = [
        # Authentication
        ('AUTH:REGISTRO', 'Creación de cuenta'),
        ('AUTH:INICIO', 'Inicio de sesión'),
        ('AUTH:INICIO_ERROR', 'Error de inicio de sesión'),
        ('AUTH:CIERRE', 'Cierre de sesión'),

        # Validation / Registration

        ('VER:VERIFICACION_ENVIADA', 'Envío de verificación'),
        ('VER:VERIFICACION', 'Verificación exitosa'),
        ('VER:VERIFICACION_REMOVIDA', 'Verificación removida'),
        ('VER:VERIFICAION_ERR', 'Error de verificación'),

        # Security
        ('SEC:CONTRASEÑA_CAMBIO', 'Cambio de contraseña'),
        ('SEC:CORREO_CAMBIO', 'Cambio de correo'),
        ('SEC:ACTIVIDAD_INUSUAL', 'Actividad inusual'),
    ]

    # Database Indexing is active on user, event_type, and timestamp for performance
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='auth_logs',
        db_index=True
    )

    username = models.CharField(max_length=25, null=True, blank=True, verbose_name="Usuario (Histórico)")

    event_type = models.CharField(
        max_length=30,
        choices=EVENT_CHOICES,
        db_index=True
    )

    # JSONField for structured metadata (Error messages, Browser context, etc.)
    metadata = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Metadatos de Seguridad"
    )

    # Network Context
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)

    # Track specialized headers
    proxy_info = models.CharField(max_length=255, null=True, blank=True, help_text="HTTP_VIA / Forwarded headers")
    accept_language = models.CharField(max_length=50, null=True, blank=True)
    session_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    user_agent = models.TextField(null=True, blank=True)

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = "Log de Autenticación"
        verbose_name_plural = "Logs de Autenticación"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.username} - {self.event_type} - {self.timestamp}"