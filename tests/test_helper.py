import pytest
from fly_jwt import *
from datetime import datetime


def test_create_refresh_token():
    token = create_refresh_token(
            payload={
                "user_id": 10
            },
            exp=60*100,
            algorithm="HS256",
            private_key="secret",
    )
    print(token)
    assert isinstance(token, str)

def test_create_access_token():
    token = create_access_token(
            payload={
                "user_id": 10
            },
            exp=60*100,
            algorithm="HS256",
            private_key="secret",
    )
    print(token)
    assert isinstance(token, str)


ALGORITHM="HS256"
SECRET="secret"
@pytest.fixture(scope="function", autouse=False)
def create_token():
    yield create_access_token(
        payload={
            "user_id": 10
        },
        exp=60*100,
        algorithm=ALGORITHM,
        private_key=SECRET,
    )

def test_decode_refresh_token(create_token):
    res = decode_refresh_token(
            create_token,
            algorithm=ALGORITHM,
            private_key=SECRET,
        )
    assert isinstance(res, dict)
    assert len(res) == 2


def test_decode_access_token(create_token):
    res = decode_access_token(
            create_token,
            algorithm=ALGORITHM,
            private_key=SECRET,
        )
    assert isinstance(res, dict)
    assert len(res) == 2
