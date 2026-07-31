from setuptools import setup, find_packages

setup(
    name="fourhdp",
    version="0.1.0",
    description="4HDP: intent-aware and state-tracking runtime defense for code-execution agents.",
    author="FourHDP Research",
    packages=find_packages(),
    install_requires=[
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "openai>=1.0.0",
        "python-dotenv>=1.0.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
    ],
    python_requires=">=3.9",
)
