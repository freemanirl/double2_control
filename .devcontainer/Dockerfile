FROM mcr.microsoft.com/devcontainers/python:3

USER vscode

RUN curl -sSL https://install.python-poetry.org | python3 -

ENV PATH="/home/vscode/.local/bin:$PATH"

# Disable Poetry's virtual env creation inside the container (use the system Python)
RUN poetry config virtualenvs.create false
