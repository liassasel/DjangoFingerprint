from django.shortcuts import render

# Create your views here.

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, permissions
from django_otp.plugins.otp_totp.models import TOTPDevice
from .models import User
from .serializers import (
    UserLoginSerializer,
    TwoFactorAuthSerializer,
    FingerprintLoginSerializer,
    UserSerializer,
    Setup2FASerializer,
    RegisterFingerprintSerializer
)
import pyotp
import qrcode
import base64
from io import BytesIO

class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = serializer.validated_data
        
        if user.is_2fa_eneabled:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                '2fa_required': True
            }, status=status.HTTP_200_OK)
            
        return self._generate_tokens_response(user)
    
class TwoFactorAuthView(APIView):
    permissions_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = TwoFactorAuthSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        device = request.user.get_otp_device()
        if device and device.verify_token(serializer.validated_data['otp']):
            return LoginView._generate_tokens_response(request.user)
        
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
    
class FingerprintLoginView(APIView):
    def post(self, request):
        serializer = FingerprintLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(fingerprint_data=serializer.validated_data['fingerprint'])
            return LoginView._generate_tokens_response(user)
        except User.DoesNotExist:
            return Response({'error': 'Invalid fingerprint'}, status=status.HTTP_404_NOT_FOUND)
        
class Setup2FAView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        if not user.otp_secret:
            user.otp_secret = pyotp.random_base32()
            user.save()
            
        serializer = Setup2FASerializer(user)
        return Response(self._generate_qr_code(user, serializer.data))
    
    def post(self, request):
        user = request.user
        serializer = TwoFactorAuthSerializer(data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        if TOTPDevice.objects.filter(user=user).exists():
            return Response({'error': '2FA already set up'}, status=status.HTTP_400_BAD_REQUEST)
        
        device = TOTPDevice.objects.create(
            user = user,
            name = 'default',
            confirmed = True,
            key = user.otp_secret,
        )
        
        if device.verify_token(serializer.validated_data['otp']):
            user.is_2fa_eneabled = True
            user.save()
            return Response({'message': '2FA setup successfully'}, status=status.HTTP_200_OK)
        
        device.delete()
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
    
    def _generate_qr_code(self, user, data):
        uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(
            name = user.email,
            issuer_name = 'DjangoFingerprint'
        )
        img = qrcode.make(uri)
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        data['qr_code'] = f'data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}'
        
        return data
        

class RegisterFingerprintView(APIView):
    permissions_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = RegisterFingerprintSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        request.user.add_fingerprint(serializer.validated_data['fingerprint'])
        return Response({'message': 'Fingerprint registered successfully'}, status=status.HTTP_200_OK)

# Method to generate tokens response
def _generate_tokens_response(user):
    refresh = RefreshToken.for_user(user)
    return Response({
        'user': UserSerializer(user).data,
        'access': str(refresh.access_token),
        'refresh': str(refresh)
    }, status=status.HTTP_200_OK)