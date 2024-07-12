# setup.py
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="MITREAttackScrapper",
    version="0.1.1",
    author="KnightChaser",
    author_email="agerio100@naver.com",
    description="A package for conveniently retrieving MITRE ATT&CK data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/KnightChaser/MITREAttackScrapper",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)