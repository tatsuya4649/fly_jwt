import pytest
from fly import Fly

@pytest.fixture(scope="function", autouse=False)
def init_fly():
    app = Fly()
    yield app

