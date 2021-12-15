import pytest
from fly_jwt import require_jwt
from fly_jwt.jwt import _fly_jwt
import jwt

TEST_CONTENT={
    "Hello": "World"
}
@pytest.fixture(scope="module", autouse=True)
def asymmetric_encoded_jwt():
    with open("conf/server.key") as f:
        key = f.read()

    encoded = jwt.encode(
        TEST_CONTENT,
        key=key,
        algorithm="RS256"
    )
    print(f"test jwt: {encoded}")
    yield encoded

@pytest.fixture(scope="module", autouse=True)
def request_test(asymmetric_encoded_jwt):
    request = dict()
    request["header"] = list()
    request["header"].append({
        "name": "Authorization",
        "value": f"Bearer {asymmetric_encoded_jwt}",
    })
    print(f"test request: {request}")
    yield request

def auth(info):
    return True

def test_decode_asymmetric(request_test, init_fly):
    @require_jwt(
        auth_handler=auth,
        algorithm="RS256",
        private_key_path="conf/server.key",
        public_key_path="conf/server.pub",
    )
    @init_fly.get("/")
    def hello(request):
        return "Hello World"

    res = _fly_jwt(request_test)
    print(f"response: {res}")
    assert(res == "Hello World")

