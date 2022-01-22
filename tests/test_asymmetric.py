import pytest
from fly_jwt import require_jwt
import jwt
import conftest

TEST_CONTENT={
    "Hello": "World"
}
@pytest.fixture(scope="module", autouse=True)
def asymmetric_encoded_jwt():
    with open(conftest.SECRETKEY) as f:
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
        private_key_path=conftest.SECRETKEY,
        public_key_path=conftest.PUBLICKEY,
    )
    @init_fly.get("/")
    def hello(request):
        return "Hello World"

    func = init_fly.routes[0]["func"]
    res = func(request_test)
    print(f"response: {res}")
    assert(res == "Hello World")

