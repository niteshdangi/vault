SHELL := /bin/bash

.PHONY: build release check fmt test clean run doctor

build:
	source "$$HOME/.cargo/env" && cargo build

release:
	source "$$HOME/.cargo/env" && cargo build --release

check:
	source "$$HOME/.cargo/env" && cargo check

fmt:
	source "$$HOME/.cargo/env" && cargo fmt

test:
	source "$$HOME/.cargo/env" && cargo test

run:
	source "$$HOME/.cargo/env" && cargo run --

doctor:
	./target/release/vault doctor

clean:
	source "$$HOME/.cargo/env" && cargo clean
