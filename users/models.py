from django.db import models

# Create your models here.

from django.contrib.auth.models import AbstractUser
from django.db import models
from django_otp.plugins.otp_totp.models import TOTPDevice

class User(AbstractUser):
    otp_secret = models.CharField(max_length=32, blank=True)
    fingerprint_data = models.JSONField(blank=True, null=True, unique=True)
    is_2fa_enabled = models.BooleanField(default=False)
    
    def get_otp_device(self):
        return TOTPDevice.objects.filter(user=self).first()
    
    def add_fingerprint(self, fingerprint):
        if not self.fingerprint_data:
            self.fingerprint_data = []
        self.fingerprint_data.append(fingerprint)
        self.save()