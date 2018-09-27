from rest_framework import serializers
from password_manager.models import Password


class PasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Password
        fields = ('id', 'username', 'organization', 'url',)


class PasswordEditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Password
        fields = ('id', 'username', 'organization', 'url', 'encrypted_password',
                  'user')


class PasswordAddSerializer(serializers.ModelSerializer):
    class Meta:
        model = Password
        fields = ('username', 'organization', 'url', 'encrypted_password',
                  'user', )
