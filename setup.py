from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="avc-parser",
    version="0.1.0",
    author="Pranav Lawate",
    author_email="pranlawate@example.com",
    description="A tool to parse SELinux AVC denial logs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pranlawate/avc-parser",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "avc-parser=parse_avc:main",
        ],
    },
)
