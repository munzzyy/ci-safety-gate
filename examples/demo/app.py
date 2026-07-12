"""A tiny stand-in for a real project, used by ci.yml to prove the gate passes on clean input."""

import os


def api_key() -> str:
    return os.environ["EXAMPLE_API_KEY"]


def greet(name: str) -> str:
    return f"hello, {name}"


if __name__ == "__main__":
    print(greet("world"))
