"""Setup script for SecureChat"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="securechat",
    version="0.1.0",
    author="SecureChat Team",
    description="End-to-End Encrypted Messaging with Signal Protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/securechat",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=[
        "PyNaCl>=1.5.0",
        "cryptography>=41.0.7",
        "protobuf>=4.25.1",
        "websockets>=12.0",
        "sqlcipher3>=0.5.2",
        "sqlalchemy>=2.0.23",
        "python-dotenv>=1.0.0",
        "click>=8.1.7",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "black>=23.12.1",
            "mypy>=1.7.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "securechat=src.client.cli:run",
            "securechat-server=src.server.main:main",
        ],
    },
)
