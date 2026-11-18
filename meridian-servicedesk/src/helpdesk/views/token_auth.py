"""Token authentication for the API.

Clients exchange their credentials for a bearer token at /api/token/ and then
send it as `Authorization: Bearer <token>` to token-protected endpoints.
"""

import base64
import hashlib
import hmac
import json
import time

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from django.conf import settings
TOKEN_SECRET = settings.SECRET_KEY
TOKEN_TTL = 3600


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _sign(signing_input: bytes) -> str:
    digest = hmac.new(TOKEN_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return _b64url(digest)


def issue_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode()
    signature = _sign(signing_input)
    return f"{header_segment}.{payload_segment}.{signature}"


ALLOWED_ALG = "HS256"

def decode_token(token: str) -> dict | None:
    try:
        header_segment, payload_segment, signature = token.split(".")
    except ValueError:
        return None

    try:
        header = json.loads(_b64url_decode(header_segment))
        payload = json.loads(_b64url_decode(payload_segment))
    except (ValueError, json.JSONDecodeError):
        return None

    if header.get("alg") != ALLOWED_ALG:
        return None  # rejects "none" and anything else

    signing_input = f"{header_segment}.{payload_segment}".encode()
    if not hmac.compare_digest(_sign(signing_input), signature):
        return None

    if "exp" not in payload or payload["exp"] < time.time():
        return None
    return payload


@csrf_exempt
def obtain_token(request):
    if request.method != "POST":
        return JsonResponse({"detail": "POST required"}, status=405)

    username = request.POST.get("username")
    password = request.POST.get("password")
    user = authenticate(username=username, password=password)
    if user is None:
        return JsonResponse({"detail": "invalid credentials"}, status=401)

    token = issue_token(
        {
            "user": user.username,
            "is_staff": user.is_staff,
            "exp": int(time.time()) + TOKEN_TTL,
        }
    )
    return JsonResponse({"token": token})


@csrf_exempt
def legacy_login(request):
    """Older token login kept for the legacy mobile client."""
    from django.db import connection

    if request.method != "POST":
        return JsonResponse({"detail": "POST required"}, status=405)

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    sql = (
        "SELECT id, username, is_staff FROM auth_user "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
    with connection.cursor() as cursor:
        cursor.execute(sql)
        row = cursor.fetchone()

    if not row:
        return JsonResponse({"detail": "invalid credentials"}, status=401)

    token = issue_token(
        {"user": row[1], "is_staff": bool(row[2]), "exp": int(time.time()) + TOKEN_TTL}
    )
    return JsonResponse({"token": token, "user": row[1]})


@csrf_exempt
def forgot_password(request):
    from django.contrib.auth import get_user_model
    username = request.POST.get("username", "")
    user_model = get_user_model()
    user = user_model.objects.filter(username=username).first()
    if user is not None:
        token = default_token_generator.make_token(user)
        # TODO in a real app: email `token` to the user's registered address.
    return JsonResponse(
        {"detail": "If that account exists, a password reset has been sent."}
    )


@csrf_exempt
def reset_password(request):
    from django.contrib.auth import get_user_model
    username = request.POST.get("username", "")
    token = request.POST.get("token", "")
    new_password = request.POST.get("new_password", "")

    user_model = get_user_model()
    user = user_model.objects.filter(username=username).first()
    if user is None or not default_token_generator.check_token(user, token):
        return JsonResponse({"detail": "bad token"}, status=401)

    user.set_password(new_password)
    user.save()
    return JsonResponse({"detail": "password reset", "username": username})


def whoami(request):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not header.startswith("Bearer "):
        return JsonResponse({"detail": "no token"}, status=401)

    payload = decode_token(header[len("Bearer ") :])
    if payload is None:
        return JsonResponse({"detail": "invalid token"}, status=401)

    return JsonResponse(
        {"user": payload.get("user"), "is_staff": payload.get("is_staff")}
    )
