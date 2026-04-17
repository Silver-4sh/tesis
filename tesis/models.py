from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.db import models


# Manager personalizado para manejar la creación de usuarios con los nuevos campos
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('El email es obligatorio')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    # Opciones para estados de cuenta
    STATUS_CHOICES = [
        ('active', 'Activa'),
        ('inactive', 'Inactiva'),
        ('blocked', 'Bloqueada'),
        ('banned', 'Eliminada'),
    ]

    # Opciones para roles
    ROLE_CHOICES = [
        ('user', 'Usuario'),
        ('admin', 'Administrador'),
    ]

    # Opciones para tipo de entidad
    ENTITY_CHOICES = [
        ('tcp', 'Trabajador por Cuenta Propia'),
        ('organization', 'Organización/Empresa'),
    ]

    # Municipios de La Habana
    MUNICIPIOS_HAVANA = [
        ('arroyo_naranjo', 'Arroyo Naranjo'),
        ('boyeros', 'Boyeros'),
        ('centro_habana', 'Centro Habana'),
        ('cerro', 'Cerro'),
        ('cotorro', 'Cotorro'),
        ('diez_de_octubre', 'Diez de Octubre'),
        ('guanabacoa', 'Guanabacoa'),
        ('habana_del_este', 'Habana del Este'),
        ('habana_vieja', 'Habana Vieja'),
        ('la_lisa', 'La Lisa'),
        ('marianao', 'Marianao'),
        ('playa', 'Playa'),
        ('plaza_revolucion', 'Plaza de la Revolución'),
        ('regla', 'Regla'),
        ('san_miguel_padron', 'San Miguel del Padrón'),
    ]

    # 5. Validador de teléfono ultra-preciso para Cuba
    # ^(\+53)? : Prefijo internacional opcional.
    # (5[0-8]\d{6} : Móviles (5 + dígito 0-8 + 6 dígitos).
    # |  7(
    #     20[1-9]|26\d|27\d|  # Playa, Marianao, La Lisa
    #     83\d|86\d|87\d|      # Plaza, Centro Habana, Habana Vieja
    #     76\d|79\d|           # Diez de Octubre, Arroyo Naranjo
    #     64\d|62\d            # Guanabacoa, Cotorro, Regla
    #   )\d{4}                 # Completa los 7 dígitos del número fijo local
    phone_validator = RegexValidator(
        regex=r'^(\+53)?(5[0-8]\d{6}|7(20|26|27|83|86|87|76|79|64|62)\d{5})$',
        message="El número debe ser un móvil (+53 5...) o un fijo válido de La Habana (+53 7...)."
    )

    # Campos base de Django y personalizados
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=150, verbose_name="Nombre Completo")
    ci = models.CharField(
        max_length=11,
        validators=[RegexValidator(r'^\d{11}$', 'El CI debe contener exactamente 11 dígitos.')],
        verbose_name="Carnet de Identidad"
    )
    location = models.CharField(max_length=50, choices=MUNICIPIOS_HAVANA, default='---')
    phone_number = models.CharField(
        max_length=12,
        blank=True,
        null=True,
        validators=[phone_validator],
        verbose_name="Teléfono (Cuba)"
    )

    # Clasificación de cuenta
    is_active = models.BooleanField(default=False)
    account_status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='blocked')
    account_verified = models.BooleanField(default=False)
    roles = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    entity_type = models.CharField(max_length=15, choices=ENTITY_CHOICES, default='---', verbose_name="Tipo de Entidad")

    # Campos de control de Django
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(blank=True, null=True, verbose_name="Último inicio de sesión")

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'

    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'

    def __str__(self):
        return f"{self.username} ({self.name})"


class AuthLogs(models.Model):
    """
    Modelo de auditoría para eventos de acceso.
    """
    EVENT_CHOICES = [
        ('login', 'Inicio de sesión'),
        ('logout', 'Cierre de sesión'),
        ('account_creation', 'Creación de cuenta'),
        ('verification', 'Verificación de cuenta'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='auth_logs')
    username = models.CharField(max_length=25, null=True, blank=True, verbose_name="Usuario (Histórico)")
    event_type = models.CharField(max_length=20, choices=EVENT_CHOICES)
    details = models.TextField(null=True, blank=True, verbose_name="Detalles del Evento")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Log de Autenticación"
        verbose_name_plural = "Logs de Autenticación"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.username} - {self.event_type} - {self.timestamp}"
