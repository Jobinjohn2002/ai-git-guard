from setuptools import setup

setup(
    name="ai-git-guard",
    version="0.1",
    py_modules=["cli", "main"],
    install_requires=[
        "typer>=0.9",
        "rich",
        "shellingham",
        "colorama",
    ],
    entry_points={
        "console_scripts": [
            "ai-git-guard=cli:app",
        ],
    },
)
