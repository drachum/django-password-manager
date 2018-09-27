from rest_framework import authentication
from rest_framework import exceptions
from django.http import HttpResponseForbidden
from password_manager.models import TemporaryKey


def require_valid_temporary_key(func):
    def wrap(request, *args, **kwargs):
        """
        TemporaryKey authentication flow goes like this:
            Premises:
                - User has a TemporaryKey registry on the database related to
                him.
                - This registry has his password encrypted with a key that was
                generated before and sent to him to be used if he want to make
                some change in any logins tables.

            After receiving a request, we will:
                1. Check if key arument is present. It is should be into the
                    request "Authorization" metadata;
                2. Check temporarykey expiration. It improves the security
                    giving a time limit to an attacker in the case of a stolen
                    key
                3. Use this key to decrypt information stored in user's
                    TemporaryKey. The result should be the user password.
                4. With these password revealed, we will check if it is valid
                using the basic "check_password" user method.
                5. If this is the right password, we will consider the user
                with all the permissions he needs to execute "logins" methods.

        """
        from password_manager.encrypt import DefaultCipher
        from base64 import b16decode

        key = request.META.get('HTTP_AUTHORIZATION', None)

        if not key:
            return HttpResponseForbidden(
                'Mandatory use of HTTP_AUTHORIZATION Temporary key',
            )
        else:
            key_b16_decoded = b16decode(key)

            try:
                temporary_key = request.user.temporary_key
            except TemporaryKey.DoesNotExist:
                return HttpResponseForbidden(
                    'User has no temporary key created'
                )

            if not temporary_key.is_valid():
                return HttpResponseForbidden('Temporary key is expired')
            else:
                # So, we build put this attribute inside user for one main
                # reason: it allows us to follow DRY and only have this code at
                # authentication point!
                cipher = DefaultCipher(key_b16_decoded)
                password_to_test = cipher.decrypt(
                        temporary_key.encrypted_password)

                if request.user.check_password(password_to_test):
                    request.user.decrypted_password = password_to_test
                    return func(request, *args, **kwargs)
                else:
                    return HttpResponseForbidden('Invalid temporary key')

    return wrap
