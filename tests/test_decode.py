import pytest
import sys
import os
sys.path.append(
    os.path.abspath("../fly")
)
from fly import Fly
from fly_jwt import require_jwt
import jwt
import conftest

@pytest.fixture(scope="function", autouse=False)
def init_fly():
    app = Fly()
    yield app

TEST_CONTENT={
    "Hello": "World"
}
@pytest.fixture(scope="module", autouse=True)
def encoded_jwt():
    with open(conftest.SECRETKEY) as f:
        key = f.read()

    encoded = jwt.encode(
        TEST_CONTENT,
        key=key,
        algorithm="HS256"
    )
    print(f"test jwt: {encoded}")
    yield encoded

@pytest.fixture(scope="module", autouse=True)
def request_test(encoded_jwt):
    request = dict()
    request["header"] = list()
    request["header"].append({
        "name": "Authorization",
        "value": f"Bearer {encoded_jwt}",
    })
    print(f"test request: {request}")
    yield request

def auth(info):
    return True

def test_decode(request_test, init_fly):
    @require_jwt(
        auth_handler=auth,
        algorithm="HS256",
        private_key_path=conftest.SECRETKEY,
    )
    @init_fly.get("/")
    def hello(request):
        return "Hello World"

    func = init_fly.routes[0]["func"]
    res = func(request_test)
    print(f"response: {res}")
    assert(res == "Hello World")
