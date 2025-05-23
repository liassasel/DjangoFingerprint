from django.urls import path
from .views import RegisterFingerprintView, Setup2FAView, FingerprintLoginView, TwoFactorAuthView, LoginView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('verify-2fa/', TwoFactorAuthView.as_view(), name='verify-2fa'),
    path('fingerprint-login/', FingerprintLoginView.as_view(), name='fingerprint-login'),
    path('setup-2fa/', Setup2FAView.as_view(), name='setup-2fa'),
    path('register-fingerprint/', RegisterFingerprintView.as_view(), name='register-fingerprint'),
]