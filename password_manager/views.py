from django.shortcuts import render
from django.views.generic import View

from django.apps import apps
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from password_manager.authentication import require_valid_temporary_key
from password_manager.models import TemporaryKey, Password
from password_manager.serializers import (PasswordSerializer,
                                          PasswordAddSerializer,
                                          PasswordEditSerializer)
from password_manager.encrypt import DefaultCipher

User = apps.get_model('auth', 'User')


class LoginsViewer(View):
    @method_decorator(login_required)
    def get(self, request):
        from django.middleware.csrf import get_token
        # Add base context
        # TODO: adding simple context to test, should change
        context = {}
        context['csrfmiddlewaretoken'] = get_token(request)
        return render(request, 'logins-viewer.html', context)


class LoginsBaseView(APIView):
    def _check_user_id_errors(self, request, user_id):
        if not user_id:
            return Response('Invalid user', status=400)

        try:
            self.user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response('Invalid user', status=400)

        if self.user != request.user:
            return Response(
                'You can only get this info from yourself', status=400)

    def _check_password_id_errors(self, request, user_id, password_id):
        user_id_errors = self._check_user_id_errors(request, user_id)

        if user_id_errors:
            return user_id_errors
        else:
            if not password_id:
                return Response('Invalid password id', status=400)
            else:
                try:
                    self.password = Password.objects.get(id=password_id)
                except Password.DoesNotExist:
                    return Response(
                        'Password id doest not exist:{0}'.format(password_id),
                        status=400
                    )


class TemporaryKeyView(LoginsBaseView):
    def post(self, request, user_id, format=None):
        from password_manager.utils import generate_temporary_key
        from base64 import b16encode

        user_id_errors = self._check_user_id_errors(request, user_id)

        if user_id_errors:
            return user_id_errors
        else:
            password = request.data.get('password')

            if not password:
                return Response('You should pass "password" data', status=400)
            else:
                try:
                    key = generate_temporary_key(request.user, password)
                except AssertionError:
                    return Response('Invalid password', status=403)

                return Response({'temporary_key': b16encode(key)})


class PasswordView(LoginsBaseView):
    @method_decorator(require_valid_temporary_key)
    def get(self, request, user_id, format=None):
        user_id_errors = self._check_user_id_errors(request, user_id)

        if user_id_errors:
            return user_id_errors
        else:
            passwords_qs = Password.objects.filter(
                user=request.user,
                deleted=False
            ).order_by('organization')

            return Response(PasswordSerializer(passwords_qs, many=True).data)

    @method_decorator(require_valid_temporary_key)
    def post(self, request, user_id, format=None):
        user_id_errors = self._check_user_id_errors(request, user_id)

        if user_id_errors:
            return user_id_errors
        else:
            data = request.data
            data['user'] = int(user_id)
            decrypted_password = data.get('password')

            # as the field on model is an encrypted_password, it makes no sense
            # to put this validation inside the serializer
            if not decrypted_password:
                return Response("You forgot to send us the password text",
                                status=400)
            else:
                # encrypting password
                cipher = DefaultCipher(request.user.decrypted_password)
                encrypted_password = cipher.encrypt(decrypted_password)
                data['encrypted_password'] = encrypted_password

                serialized = PasswordAddSerializer(data=data)
                if serialized.is_valid():
                    db_password = serialized.save()
                    return Response(PasswordSerializer(db_password).data)
                else:
                    return Response(serialized.errors, status=400)


class PasswordItemView(LoginsBaseView):
    @method_decorator(require_valid_temporary_key)
    def get(self, request, user_id, password_id, format=None):
        password_id_errors = self._check_password_id_errors(request,
                                                            user_id,
                                                            password_id)
        if password_id_errors:
            return password_id_errors
        else:
            db_password = Password.objects.get(id=password_id)

            # decrypting user password
            cipher = DefaultCipher(request.user.decrypted_password)
            decrypted_password = cipher.decrypt(db_password.encrypted_password)

            # building password json to return
            password_json = PasswordSerializer(db_password).data
            password_json['password'] = decrypted_password

            return Response(password_json, status=200)

    @method_decorator(require_valid_temporary_key)
    def put(self, request, user_id, password_id, format=None):
        user_id_errors = self._check_user_id_errors(request, user_id)

        password_id_errors = self._check_password_id_errors(request,
                                                            user_id,
                                                            password_id)
        if password_id_errors:
            return password_id_errors
        else:
            data = request.data
            data['id'] = password_id
            decrypted_password = data.get('password')

            if decrypted_password:
                # encrypting password
                cipher = DefaultCipher(request.user.decrypted_password)
                encrypted_password = cipher.encrypt(decrypted_password)
                data['encrypted_password'] = encrypted_password
                data['user'] = int(user_id)

            db_password = Password.objects.get(id=password_id)
            serialized = PasswordEditSerializer(db_password, data=data)

            if serialized.is_valid():
                db_password = serialized.save()
                return Response(PasswordSerializer(db_password).data)
            else:
                return Response(serialized.errors, status=400)

    @method_decorator(require_valid_temporary_key)
    def delete(self, request, user_id, password_id, format=None):
        password_id_errors = self._check_password_id_errors(request,
                                                            user_id,
                                                            password_id)
        if password_id_errors:
            return password_id_errors
        else:
            Password.objects.filter(id=password_id).update(deleted=True)
            return Response(status=204)
