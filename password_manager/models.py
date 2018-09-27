from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils import timezone
from django.apps import apps


@python_2_unicode_compatible
class Password(models.Model):
    user = models.ForeignKey(
        'auth.User',
        related_name='passwords_encrypted',
        on_delete=models.CASCADE
    )
    username = models.CharField(max_length=200, null=False, blank=False)
    encrypted_password = models.TextField(null=False, blank=False)
    organization = models.CharField(max_length=200, null=False, blank=False)
    url = models.URLField(null=True, blank=True)
    time_created = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    deleted = models.BooleanField(default=False)

    def __str__(self):
        return "{0} > {1} > {2}".format(self.user.email,
                                        self.organization,
                                        self.username)


@python_2_unicode_compatible
class TemporaryKey(models.Model):
    user = models.OneToOneField('auth.User',
                                on_delete=models.CASCADE,
                                primary_key=True,
                                related_name='temporary_key')
    encrypted_password = models.TextField(null=False, blank=False)
    expires_at = models.DateTimeField(null=False, blank=False)

    def is_valid(self):
        # Get ever the newer version from database
        self.refresh_from_db()
        return timezone.now() < self.expires_at

    def __str__(self):
        return "{0}".format(self.user.username)
