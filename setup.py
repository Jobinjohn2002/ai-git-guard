from setuptools import setup

setup(
    name="ai-git-guard",
    version="0.1.0",  # must be a valid semver string
    py_modules=["cli"],
    install_requires=[
        "typer>=0.9",
        "rich",
        "shellingham",
        "colorama",
        "python-dotenv",
        "google-generativeai",
    ],
    entry_points={
        "console_scripts": [
            "ai-git-guard=cli:main",  # use cli.py's main()
        ],
    },
)
