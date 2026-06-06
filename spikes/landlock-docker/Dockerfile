FROM rust:1.88-slim
WORKDIR /spike
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release
CMD ["./target/release/landlock-spike"]
