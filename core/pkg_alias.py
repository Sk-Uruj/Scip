"""PyPI distribution names are not import names, and many dependencies are never imported directly.

The call graph records ``import yaml`` as the node ``pkg::yaml``. A vulnerability report talks about
the distribution ``PyYAML``. Looking up ``pkg::pyyaml`` therefore never finds it, and a library that
is imported and called inside an HTTP route used to be reported as DEAD code (and its risk cut).

This module provides:
  * import_names(dist)   - the top-level import names for a distribution
  * import_names_known() - whether SCIP is confident about those names (only then may a package that
                           is not imported be called DEAD; otherwise it is UNKNOWN)
  * parents_of(dist)     - packages that depend on ``dist`` (transitive dependencies inherit the
                           exposure of the package that pulls them in)

The tables are deliberately explicit and conservative; extend them rather than guessing.
"""
from __future__ import annotations

import re
from typing import Dict, List

# distribution (normalised) -> top-level import names
IMPORT_NAMES: Dict[str, List[str]] = {
    "pyyaml": ["yaml"], "ruamel-yaml": ["ruamel"], "pillow": ["PIL"], "pyjwt": ["jwt"],
    "python-jose": ["jose"], "beautifulsoup4": ["bs4"], "scikit-learn": ["sklearn"],
    "scikit-image": ["skimage"], "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"],
    "opencv-contrib-python": ["cv2"], "python-dateutil": ["dateutil"], "python-dotenv": ["dotenv"],
    "pycryptodome": ["Crypto"], "pycryptodomex": ["Cryptodome"], "pyopenssl": ["OpenSSL"],
    "attrs": ["attr", "attrs"], "msgpack-python": ["msgpack"], "mysqlclient": ["MySQLdb"],
    "pymysql": ["pymysql"], "psycopg2-binary": ["psycopg2"], "psycopg2": ["psycopg2"],
    "python-magic": ["magic"], "pyzmq": ["zmq"], "pymongo": ["pymongo", "bson", "gridfs"],
    "gitpython": ["git"], "python-ldap": ["ldap"], "pyserial": ["serial"],
    "websocket-client": ["websocket"], "python-slugify": ["slugify"], "python-multipart": ["multipart"],
    "typing-extensions": ["typing_extensions"], "charset-normalizer": ["charset_normalizer"],
    "argon2-cffi": ["argon2"], "setuptools": ["setuptools", "pkg_resources"], "protobuf": ["google"],
    "google-api-python-client": ["googleapiclient"], "pyasn1-modules": ["pyasn1_modules"],
    "discord-py": ["discord"], "python-telegram-bot": ["telegram"], "pytest-cov": ["pytest_cov"],
    "pyparsing": ["pyparsing"], "importlib-metadata": ["importlib_metadata"],
    # Django ecosystem
    "django-allauth": ["allauth"], "djangorestframework": ["rest_framework"],
    "django-cors-headers": ["corsheaders"], "django-filter": ["django_filters"],
    "django-environ": ["environ"], "django-extensions": ["django_extensions"],
    "django-crispy-forms": ["crispy_forms"], "django-debug-toolbar": ["debug_toolbar"],
    "django-storages": ["storages"], "django-redis": ["django_redis"], "django-celery-beat": ["django_celery_beat"],
    "djangorestframework-simplejwt": ["rest_framework_simplejwt"],
    # Flask ecosystem
    "flask-sqlalchemy": ["flask_sqlalchemy"], "flask-login": ["flask_login"], "flask-cors": ["flask_cors"],
    "flask-wtf": ["flask_wtf"], "flask-migrate": ["flask_migrate"], "flask-restful": ["flask_restful"],
    "flask-jwt-extended": ["flask_jwt_extended"], "flask-limiter": ["flask_limiter"],
    "requests-oauthlib": ["requests_oauthlib"], "markdown": ["markdown"],
}

# distributions whose import name equals the (underscored) distribution name
SIMPLE_NAMES = {
    "django", "flask", "requests", "urllib3", "jinja2", "werkzeug", "markupsafe", "itsdangerous", "click",
    "idna", "certifi", "sqlparse", "asgiref", "tzdata", "gunicorn", "uvicorn", "starlette", "fastapi",
    "pydantic", "celery", "kombu", "billiard", "vine", "amqp", "numpy", "pandas", "scipy", "matplotlib",
    "sqlalchemy", "alembic", "cryptography", "paramiko", "bcrypt", "passlib", "lxml", "oauthlib", "boto3",
    "botocore", "s3transfer", "jmespath", "pytz", "redis", "aiohttp", "httpx", "httpcore", "anyio", "sniffio",
    "h11", "yarl", "multidict", "frozenlist", "aiosignal", "greenlet", "pytest", "pluggy", "iniconfig",
    "packaging", "tqdm", "rich", "typer", "jsonschema", "toml", "tomli", "six", "chardet", "cffi",
    "pycparser", "docutils", "pygments", "tornado", "twisted", "selenium", "scrapy", "torch", "tensorflow",
    "keras", "transformers", "flask_cors", "gevent", "eventlet", "waitress", "mako", "httplib2", "zipp",
}

# parent distribution -> distributions it pulls in (known, stable relationships only)
TRANSITIVE: Dict[str, List[str]] = {
    "django": ["asgiref", "sqlparse", "tzdata"],
    "djangorestframework": ["django", "pytz"],
    "django-allauth": ["django", "requests-oauthlib", "oauthlib", "pyjwt", "cryptography", "requests"],
    "flask": ["werkzeug", "jinja2", "itsdangerous", "click", "markupsafe", "blinker"],
    "requests": ["urllib3", "idna", "certifi", "charset-normalizer"],
    "requests-oauthlib": ["oauthlib", "requests"],
    "jinja2": ["markupsafe"], "werkzeug": ["markupsafe"],
    "celery": ["kombu", "billiard", "vine", "click", "tzdata", "python-dateutil", "amqp"],
    "kombu": ["amqp", "vine"],
    "fastapi": ["starlette", "pydantic", "typing-extensions"],
    "starlette": ["anyio"], "pydantic": ["pydantic-core", "annotated-types", "typing-extensions"],
    "anyio": ["idna", "sniffio"],
    "sqlalchemy": ["greenlet", "typing-extensions"], "alembic": ["sqlalchemy", "mako"],
    "pyopenssl": ["cryptography"], "paramiko": ["cryptography", "bcrypt", "pynacl"],
    "cryptography": ["cffi"], "cffi": ["pycparser"],
    "boto3": ["botocore", "jmespath", "s3transfer"], "botocore": ["urllib3", "jmespath", "python-dateutil"],
    "pandas": ["numpy", "python-dateutil", "pytz", "tzdata"], "scipy": ["numpy"],
    "matplotlib": ["numpy", "pillow", "pyparsing", "python-dateutil", "packaging"],
    "scikit-learn": ["numpy", "scipy", "joblib", "threadpoolctl"],
    "uvicorn": ["click", "h11"], "gunicorn": ["packaging"],
    "httpx": ["httpcore", "anyio", "certifi", "idna", "sniffio"], "httpcore": ["h11", "certifi"],
    "aiohttp": ["aiosignal", "frozenlist", "multidict", "yarl", "attrs"],
    "selenium": ["urllib3", "certifi", "trio"],
    "pytest": ["pluggy", "iniconfig", "packaging"],
}

_PARENTS: Dict[str, List[str]] = {}
for _parent, _children in TRANSITIVE.items():
    for _child in _children:
        _PARENTS.setdefault(_child, []).append(_parent)


def normalize_dist(name: str) -> str:
    """PEP 503 normalisation: 'PyYAML', 'pyyaml' and 'Py_YAML' all map to the same key."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def import_names(dist: str) -> List[str]:
    """Lower-cased top-level import names to look for (graph nodes are stored lower-cased)."""
    norm = normalize_dist(dist)
    names = [n.lower() for n in IMPORT_NAMES.get(norm, [])]
    for fallback in (norm.replace("-", "_"), norm, (dist or "").lower()):
        if fallback and fallback not in names:
            names.append(fallback)
    return names


def import_names_known(dist: str) -> bool:
    """True when we are confident which name this package is imported under."""
    norm = normalize_dist(dist)
    return norm in IMPORT_NAMES or norm.replace("-", "_") in SIMPLE_NAMES or norm in SIMPLE_NAMES


def parents_of(dist: str) -> List[str]:
    return list(_PARENTS.get(normalize_dist(dist), []))
