FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY murx ./murx
RUN pip install --no-cache-dir .
COPY examples ./examples
ENTRYPOINT ["python", "examples/docker_demo.py"]
