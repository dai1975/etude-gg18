all:
	cargo build

test:
	RUST_BACKTRACE=0 cargo test -- --nocapture

test1:
	RUST_BACKTRACE=1 cargo test -- --nocapture
