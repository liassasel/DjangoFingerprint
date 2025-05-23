from django.db.models.signals import pre_delete
from django.dispatch import receiver
from .models import User

@receiver(pre_delete, sender=User)
def delete_otp_devices(sender, instance, **kwargs):
    TOTPDevice.objects.filter(user=instance).delete()