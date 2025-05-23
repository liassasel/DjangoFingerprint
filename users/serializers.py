from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User

class UserLoginSerializer(serializers.Serializer):
    user = serializers.CharField()
    password = serializers.Charfield(write_only=True)
    
    def validate(self, attrs):
        user = authenticate(username=attrs['username'], password=attrs['password'])
        
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        
        if not user.is_active:
            raise serializers.ValidationError('User is inactive')
        
        return user
    
class TwoFactorAuthSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
    
class FingerPrintLoginSerializer(serializers.Serializer):
    fingerprint = serializers.CharField()
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_2fa_enabled']
        read_only_fields = ['is_2fa_enabled']
        
class Setup2FASerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['otp_secret']
        read_only_fields = ['otp_secret']
        
class RegisterFingerprintSerializer(serializers.Serializer):
    fingerprint = serializers.CharField()