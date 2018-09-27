# Django Password Manager

**Store passwords safely inside Django.**

---

# Glossary

1. PasswordItem: we will call an PasswordItem every login/password user decides
   to safely stores inside Logins<sup>TM</sup> app.
2. key: a key that is used crypto algorithms to encrypt its information;
3. temporary key: we use it to refer to the temporary key we use in our
   solution to encrypt user's plain text password inside our database;
4. TemporaryKey: it is used to refer to a table inside our database.

# Premisses

This implementation is based on some important premises:

1. Nobody, apart from the user, should have access to her password. It includes
   our server. We will not have a way to recover PasswordItems without a help
   from the client. It makes user password TRULY secure.
2. PasswordItems must be stored with a high level security algorithm using a 256
   bits key. We choose AES.
3. The Man-in-the-Middle security flaw is not a concern to us. We assume that
   the app WILL EVER use HTTPS as its protocol, so that it is already
   solved.
4. We know that the solution given here might keep only one possible flaw: the
   theft of temporary key from its javascript. We solved that by deciding
   that each temporary key will have a SHORT period of operation. This way, an
   attacker would have a little bit of time to explore it. The only way we can
   see now she can do that is by opening user browser and getting the temporary
   key from JS console.
5. When the user enters in Django Password Manager App she will need to
   inform her assword again.

---

# Overview

Briefly speaking, the solution implemented here has has the following flow:

1. User inform her django password to enter in Django Password Manager app;
2. We store her password inside TemporaryKey table encrypted by a random key.
   This key is returned to the user;
3. All other requests might use the temporary key to be considered as
   authentic.
4. When the user creates a new PasswordItem we will use
   temporary key to decrypt the user password stored in our database and, after
   that, the same password to encrypt PasswordItem password. So that, the only
   way to decrypt it is by having user plain text pass.
5. No we have a secure pass stored in PasswordItem. If user wants to get it
   again she will need to send us a valid temporary key and it will be
   decrypted to her.

* PS.: all keys are encrypted by using a 256 bits AES approach.

---

# Approach Part 1 - Temporary Key Flow

It is important to understand that the main goal of this approach is to store
user password safely. In a way that we might have access to its value to use
that as a key for PasswordItem password.

The approach we use for temporary key is the following:

When the user logins in the app she will offer its django pass.
We will get her password and store it in the database, encrypted by a special
key. This key is random and has 256 bits. It is called *temporary key* and the
only entity that knows its value is the user's JavaScript.

Hereafter we have something like a vault. This vault contains user password
stored on a table called TemporaryKey, but the only way to
open this box is by using a key that was returned and it is ONLY in user's
browser. An important aspect is that this key can only be used in a time
window, which adds a new security layer to the process.

                             _____________
                            |             |
                            |     ___     |
                            |    |key|    |
                            |     ---     |
                            |  encrypted  |
                            |  userpass   |
                            |_____________|


* key is valid for a time window (decided by expires_at property on the
  TemporaryKey table);
* the vault's key is the temporary key that only the user has access to;
* with a key, we can open the vault and get user's plaint text password.


# Approach Part 2 - Logins Items (Password) Flow

Using approach 1 make it possible to get user plain text password safely, which
is the base for what we will do next.

Apart from using temporary key as a key to our special Authentication
Method (notice that is used only in this app and we use Authentication HTTP
header to that), we also use temporary key in the process of
edit/add/get PasswordItems. The edit/add/get process works the same way.
Let's explain the add process:

The user sends us password, organization, username fields that she decided
to store as a PasswordItem. Now, we need to encrypt the password. To do that we
choose an AES 256 bits cipher, using as a key the user django password.

To get this plain text pass, we use the temporary key to decrypt user password
stored on our database and, after having this, we use it as a key to our AES
cipher which is used to encrypt PasswordItem password info.

Every time when a user want to get some entries in the database she will need
to pass us a PrimaryKey. Without this information, it is IMPOSSIBLE to get any
sensible data!

                             _____________
                            |             |
                            |     ___     |
                            |    |key|    |
                            |     ---     |
                            |  encrypted  |
                            |  entrypass  |
                            |_____________|


* key is user's django password and it is valid forever;
* inside the box we have one password related to the entry added by the user.
