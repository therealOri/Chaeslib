import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="Chaeslib",
    version="1.0.1",
    author="therealOri",
    license="GPL-3.0",
    install_requires=[
        "alive-progress",
        "pycryptodome",
        "argon2-cffi"
    ],
    author_email="therealOri@duck.com",
    description="A minimalistic and simple AES256-GCM+ChaCha20_Poly1305 library. For encrypting data using both 'AES256-GCM' & 'ChaCha20_Poly1305'.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/therealOri/Chaeslib",
)
