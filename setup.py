from setuptools import setup, find_packages

setup(
    name="certchecker",
    version="1.0.0",
    description="A powerful SSL/TLS certificate inspection CLI tool",
    author="CertChecker",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "cryptography>=41.0.0",
        "requests>=2.31.0",
        "dnspython>=2.4.0",
    ],
    entry_points={
        "console_scripts": [
            "certchecker=certchecker.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet",
    ],
)
