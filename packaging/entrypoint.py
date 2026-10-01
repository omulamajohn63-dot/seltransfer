"""PyInstaller entry point for the SELTRANSFER executable.

``pyproject.toml`` points the ``seltransfer`` console script at
``seltransfer.cli:app``, which is a Typer object rather than a plain function.
PyInstaller needs a real module attribute to import and call, so this shim gives
it one.

Keeping it separate from ``cli.py`` means the application package never has to
know it is being frozen, and the module is three lines long enough to audit.
"""

from seltransfer.cli import app

if __name__ == "__main__":
    app()
