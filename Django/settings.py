"""
Django settings for Django project.

Generated by 'django-admin startproject' using Django 4.2.5.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_USER_MODEL='Linkfeed.User'
# X_FRAME_OPTIONS = 'ALLOWALL'
# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-l4p+leivf2)ww%r0)9f@m_2i@08_8b&gp=$b^t6bp@ty-j_!jp"

# SECURITY WARNING: don't run with debug turned on in production!git
DEBUG = True

ALLOWED_HOSTS = ["*"]
LOGIN_URL = '/Linkfeed/index/'
# ALLOW_IFRAMING_WITHOUT_REFERER = False # Disallow if Referer is mi
EXPLICIT_TRUSTED_DOMAIN = 'http://127.0.0.1:8000'  # Replace with your desired domain

# CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:8000"]
# # SESSION_COOKIE_SECURE = False
# SESSION_COOKIE_SECURE = False


# SESSION_COOKIE_SAMESITE = 'None'
# CSRF_COOKIE_SAMESITE = 'None'
# CSRF_COOKIE_SECURE = True

# SECURE_SSL_REDIRECT = False

# CSP_DEFAULT_SRC = ("'self'", "http://127.0.0.1:8000")

# CORS (Cross-Origin Resource Sharing)
# Example allowing CORS from a specific domain
# CORS_ORIGIN_ALLOW_ALL = True

# Application definition

INSTALLED_APPS = [
    "Linkfeed",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]
# from Linkfeed.decorators import prevent_iframe_embedding 

MIDDLEWARE = [
   
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "Django.urls"

AUTH_USER_MODEL='Linkfeed.User'
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages"
            ],
        },
    },
]

WSGI_APPLICATION = "Django.wsgi.application"


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"