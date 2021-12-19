from setuptools import setup

def _requirements():
    with open("./requirements.txt", "r") as fp:
        return fp.readlines()

setup(
    name="fly_jwt",
    version="0.1.1",
    install_requires=_requirements(),
    extras_require={
        "develop": [
            "pytest >= 6.2.5",
        ]
    },
)
