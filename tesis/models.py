from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, Group, AbstractUser
from django.core.validators import RegexValidator
from django.db import models

from EcoCircular import settings


class CustomUser(AbstractUser, PermissionsMixin):
    ENTITY_CHOICES = [
        ('tcp', 'Trabajador por Cuenta Propia'),
        ('organization', 'Organización/Empresa'),
    ]

    MUNICIPIOS_HAVANA = [
        ('arroyo_naranjo', 'Arroyo Naranjo'), ('boyeros', 'Boyeros'),
        ('centro_habana', 'Centro Habana'), ('cerro', 'Cerro'),
        ('cotorro', 'Cotorro'), ('diez_de_octubre', 'Diez de Octubre'),
        ('guanabacoa', 'Guanabacoa'), ('habana_del_este', 'Habana del Este'),
        ('habana_vieja', 'Habana Vieja'), ('la_lisa', 'La Lisa'),
        ('marianao', 'Marianao'), ('playa', 'Playa'),
        ('plaza_revolucion', 'Plaza de la Revolución'), ('regla', 'Regla'),
        ('san_miguel_padron', 'San Miguel del Padrón'),
    ]

    phone_validator = RegexValidator(
        regex=r'^(5\d{7})$',
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

    ci = models.CharField(
        max_length=11, null=True, blank=True,
        validators=[RegexValidator(r'^\d{11}$', 'El CI debe contener exactamente 11 dígitos.')],
        unique=True, verbose_name="Carnet de Identidad"
    )
    phone_number = models.CharField(
        max_length=12, blank=True, null=True,
        validators=[phone_validator], unique=True, verbose_name="Teléfono"
    )
    location = models.CharField(max_length=50, choices=MUNICIPIOS_HAVANA, default='---', verbose_name="Ubicación")
    entity_type = models.CharField(max_length=15, choices=ENTITY_CHOICES, default='---', verbose_name="Tipo de Entidad")
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'username'  # This tells Django which field to use for login
    REQUIRED_FIELDS = ['email']  # Fields prompted when running 'createsuperuser'

    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
        permissions = [
            ("change_user_data", "Puede editar campos de usuario"),
            ("change_admin_data", "Puede editar campos de administrador"),
            ("change_own_data", "Puede editar sus datos"),
            ("change_other_data", "Puede editar datos de otros usuarios"),
        ]

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def __str__(self):
        full_name = self.get_full_name()
        return f"{self.username} ({full_name})" if full_name else self.username


class Logs(models.Model):
    # Use Prefixes for better filtering: AUTH (Session), SEC (Security), VAL (Verification/Registration)
    EVENT_CHOICES = [
        # Authentication
        ('AUTH:INICIO', 'Inicio de sesión'),
        ('AUTH:INICIO_ERR', 'Error de inicio de sesión'),
        ('AUTH:CIERRE', 'Cierre de sesión'),

        # Validation / Registration
        ('VAL:REGISTRO', 'Creación de cuenta'),
        ('VAL:VERIFICACION_ENVIADA', 'Envío de verificación'),
        ('VAL:VERIFICACION', 'Verificación exitosa'),
        ('VAL:VERIFICAION_ERR', 'Error de verificación'),

        # Security
        ('SEC:CONTRASEÑA_CAMBIO', 'Cambio de contraseña'),
        ('SEC:CORREO_CAMBIO', 'Cambio de email'),
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