import pytest
from fly_jwt.config import _JWTConfig

@pytest.fixture(scope="function", autouse=False)
def jwt_hs_init():
    _jwt = _JWTConfig(
        hello,
        algorithm="HS256",
        private_key="secret",
        auth_handler=auth_handler,
    )
    yield _jwt

@pytest.fixture(scope="function", autouse=False)
def jwt_rs_init():
    _jwt = _JWTConfig(
        hello,
        algorithm="RS256",
        private_key="secret",
        public_key="public",
        auth_handler=auth_handler,
    )
    yield _jwt

def test_config():
    with pytest.raises(TypeError) as e:
        _JWTConfig()

def hello():
    print("Hello World")

def auth_handler():
    print("authentication")

def test_config_init_algorithm():
    # no algorithm error
    with pytest.raises(ValueError) as e:
        _JWTConfig(
            hello
        )

def test_config_init_algorithm_key():
    # no private key error
    with pytest.raises(KeyError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
        )

def test_config_auth_handler_error():
    # no authentication error
    with pytest.raises(TypeError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
            private_key="secret",
        )

@pytest.mark.parametrize(
    "auth_handler", [
    1.0,
    1,
    "auth_handler",
    b"auth_handler",
    [], {}, ()
])
def test_config_auth_handler_type_error(auth_handler):
    with pytest.raises(TypeError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
            private_key="secret",
            auth_handler=auth_handler,
        )

def test_config_pri_key_path_error():
    # private key and key path setting error
    with pytest.raises(KeyError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
            private_key="secret",
            private_key_path="secret_path",
            auth_handler=auth_handler,
        )

@pytest.mark.parametrize(
    "private", [
    1,
    1.0,
    b"hello",
    {}, [], ()
])
def test_config_private_key_type_error(private):
    with pytest.raises(TypeError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
            private_key=private,
            auth_handler=auth_handler,
        )

@pytest.mark.parametrize(
    "private_path", [
    1,
    1.0,
    b"hello",
    {}, [], ()
])
def test_config_private_key_path_type_error(private_path):
    with pytest.raises(TypeError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
            private_key_path=private_path,
            auth_handler=auth_handler,
        )

def test_config_private_key_path_value_error():
    with pytest.raises(FileNotFoundError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
            private_key_path="test",
            auth_handler=auth_handler,
        )

def test_config_public_key_error():
    # private key and key path setting error
    with pytest.raises(ValueError) as e:
        _JWTConfig(
            hello,
            algorithm="HS256",
            private_key="secret",
            public_key="public",
            auth_handler=auth_handler,
        )

@pytest.mark.parametrize(
    "public", [
    1,
    1.0,
    b"hello",
    {}, [], ()
])
def test_config_public_key_type_error(public):
    # public key type error
    with pytest.raises(TypeError) as e:
        _JWTConfig(
            hello,
            algorithm="RS256",
            private_key="secret",
            public_key=public,
            auth_handler=auth_handler,
        )

@pytest.mark.parametrize(
    "public_path", [
    1,
    1.0,
    b"hello",
    {}, [], ()
])
def test_config_public_key_path_type_error(public_path):
    # public key type error
    with pytest.raises(TypeError) as e:
        _JWTConfig(
            hello,
            algorithm="RS256",
            private_key="secret",
            public_key_path=public_path,
            auth_handler=auth_handler,
        )

def test_config_public_key_path_value_error():
    # not found public key path error
    with pytest.raises(FileNotFoundError) as e:
        _JWTConfig(
            hello,
            algorithm="RS256",
            private_key="private",
            public_key_path="test",
            auth_handler=auth_handler,
        )

def test_config_no_public_key_error():
    # no public key
    with pytest.raises(KeyError) as e:
        _JWTConfig(
            hello,
            algorithm="RS256",
            private_key="secret",
            auth_handler=auth_handler,
        )

def test_config_public_key_path_error():
    # no public key
    with pytest.raises(KeyError) as e:
        _JWTConfig(
            hello,
            algorithm="RS256",
            private_key="secret",
            public_Key="public",
            public_Key_path="public_path",
            auth_handler=auth_handler,
        )

def test_config_init():
    _JWTConfig(
        hello,
        algorithm="HS256",
        private_key="secret",
        auth_handler=auth_handler,
    )

def test_algorithm(jwt_hs_init):
    al = jwt_hs_init.algorithm
    assert isinstance(al, str)

def test_private_key(jwt_hs_init):
    res = jwt_hs_init.private_key
    assert isinstance(res, str)

def test_public_key(jwt_rs_init):
    res = jwt_rs_init.public_key
    assert isinstance(res, str)

def test_is_symmetric(jwt_hs_init, jwt_rs_init):
    assert jwt_hs_init._is_symmetric() is True
    assert jwt_rs_init._is_symmetric() is False

def test_fail_handler(jwt_hs_init):
    def fail_handler():
        print("Hello")

    _jwt = _JWTConfig(
        hello,
        algorithm="HS256",
        private_key="secret",
        auth_handler=auth_handler,
        fail_handler=fail_handler,
    )
    assert jwt_hs_init.fail_handler is None
    assert _jwt.fail_handler is fail_handler

def test_success_handler(jwt_hs_init, jwt_rs_init):
    assert jwt_hs_init.success_handler is hello
    assert jwt_rs_init.success_handler is hello

def test_auth_handler(jwt_hs_init, jwt_rs_init):
    assert jwt_hs_init.auth_handler is auth_handler
    assert jwt_rs_init.auth_handler is auth_handler
