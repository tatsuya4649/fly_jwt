import pytest
from fly import Fly
from fly.exceptions import HTTP401Exception
from fly_jwt import require_jwt
from fly_jwt.jwt import *
import jwt

def auth_handler(decoded):
    print(decoded)
    print("AUTH")

def auth_handler_fail(decoded):
    return False

def auth_handler_type_error(decoded):
    pass

def fail_handler(error_content):
    raise HTTP401Exception(error_content)

@pytest.fixture(scope="function", autouse=False)
def token():
    encoded = jwt.encode(
            {
                "test": "fly_jwt",
            },
            key="secret",
            algorithm="HS256"
            )
    yield encoded

@pytest.fixture(scope="function", autouse=False)
def invalid_token():
    encoded = jwt.encode(
            {
                "test": "fly_jwt",
            },
            key="secret1",
            algorithm="HS256"
            )
    yield encoded

@pytest.fixture(scope="function", autouse=False)
def http_request(token):
    _req = dict()
    _req["header"] = list()
    _req["header"].append({
        "name": "Authorization",
        "value": f"Bearer {token}",
    })
    yield _req

@pytest.fixture(scope="function", autouse=False)
def http_request_invalid_token(invalid_token):
    _req = dict()
    _req["header"] = list()
    _req["header"].append({
        "name": "Authorization",
        "value": f"Bearer {invalid_token}",
    })
    yield _req

def test_jwt_fail_handler(token, http_request, init_fly):
    def hello(request):
        return None

    _hello = init_fly.get("/")(hello)
    _fly_jwt = require_jwt(
            auth_handler=auth_handler,
            algorithm="HS256",
            private_key="secret",
            fail_handler=fail_handler
            )(_hello)

    with pytest.raises(Exception):
        _fly_jwt(http_request)

def test_jwt_fail_handler_no_header(token, init_fly):
    def hello(request):
        return None

    _hello = init_fly.get("/")(hello)
    _fly_jwt = require_jwt(
        auth_handler=auth_handler,
        algorithm="HS256",
        private_key="secret",
        fail_handler=fail_handler
            )(_hello)

    http_invalid_request = dict()
    with pytest.raises(HTTP401Exception) as e:
        _fly_jwt(http_invalid_request)

    print(e)

def test_jwt_fail_handler_invalid_token(http_request_invalid_token, init_fly):
    def hello(request):
        return None

    _hello = init_fly.get("/")(hello)
    _fly_jwt = require_jwt(
        auth_handler=auth_handler,
        algorithm="HS256",
        private_key="secret",
        fail_handler=fail_handler
            )(_hello)

    with pytest.raises(HTTP401Exception) as e:
        _fly_jwt(http_request_invalid_token)

    print(e)


def test_jwt_auth_handler_fail(http_request, init_fly):
    def hello(request):
        return None

    _hello = init_fly.get("/")(hello)
    _fly_jwt = require_jwt(
        auth_handler=auth_handler_fail,
        algorithm="HS256",
        private_key="secret",
            )(_hello)
    with pytest.raises(HTTP401Exception) as e:
        _fly_jwt(http_request)
    print(e)


def test_jwt_auth_handler_type_error(http_request, init_fly):
    def hello(request):
        return None

    _hello = init_fly.get("/")(hello)
    _fly_jwt = require_jwt(
        auth_handler=auth_handler_type_error,
        algorithm="HS256",
        private_key="secret",
            )(_hello)
    with pytest.raises(HTTP401Exception) as e:
        _fly_jwt(http_request)
    print(e)

