FROM rust:latest AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM python:3.10-slim
COPY --from=builder /app/target/release/librust_extensions.so /app/
COPY requirements.txt .
RUN pip install -r requirements.txt
CMD ["python", "src/main.py"]