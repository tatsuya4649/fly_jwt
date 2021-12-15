import pytest
import sys
import os
sys.path.append(
    os.path.abspath("../fly")
)
from fly import Fly
from fly_jwt import require_jwt
from fly_jwt.jwt import _fly_jwt
from fly_jwt.config import _JWTConfig
import jwt

@pytest.fixture(scope="function", autouse=False)
def init_fly():
    app = Fly()
    yield app

TEST_CONTENT={
    "Hello": "World"
}
@pytest.fixture(scope="module", autouse=True)
def symmetric_encoded_jwt():
    with open("server.key") as f:
        key = f.read()

    encoded = jwt.encode(
        TEST_CONTENT,
        key=key,
        algorithm="HS256"
    )
    print(f"test jwt: {encoded}")
    yield encoded

@pytest.fixture(scope="module", autouse=True)
def request_test(symmetric_encoded_jwt):
    request = dict()
    request["header"] = list()
    request["header"].append({
        "name": "Authorization",
        "value": f"Bearer {symmetric_encoded_jwt}",
    })
    print(f"test request: {request}")
    yield request

def auth(info):
    return True

def test_decode_symmetric(request_test, init_fly):
    @require_jwt(
        auth_handler=auth,
        algorithm="HS256",
        private_key_path="server.key",
    )
    @init_fly.get("/")
    def hello(request):
        return "Hello World"

    res = _fly_jwt(request_test)
    print(f"response: {res}")
    assert(res == "Hello World")

def success_call():
    return None

def test_public_error():

    with pytest.raises(ValueError):
        conf = _JWTConfig(
            success_call,
            public_key="secret",
        )

@pytest.mark.parametrize(
    "call", [
    1,
    1.0,
    [],
    {},
    "call"
])
def test_call_error(call):
    with pytest.raises(TypeError):
        conf = _JWTConfig({
            call
        })

def test_algorithm_error():
    with pytest.raises(ValueError):
        conf = _JWTConfig(
            success_call
        )

@pytest.mark.parametrize(
    "algo", [
    1,
    1.0,
    [],
    {},
])
def test_algorithm_type_error(algo):
    with pytest.raises(TypeError):
        conf = _JWTConfig(
            success_call,
            algorithm=algo
        )

def test_algorithm_unknown_algo():
    with pytest.raises(ValueError):
        conf = _JWTConfig(
            success_call,
            algorithm="FLY_JWT"
        )
