from django.conf import settings
from django.core.mail import EmailMultiAlternatives


def send_email_task(subject, text_content, html_content, email_from=None, email_to=None):
    sender = email_from if email_from else settings.DEFAULT_FROM_EMAIL
    receiver = email_to if email_to else settings.DEFAULT_FROM_EMAIL

    mail = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=sender,
        to=[receiver]
    )
    mail.attach_alternative(html_content, "text/html")
    mail.send(fail_silently=False)
