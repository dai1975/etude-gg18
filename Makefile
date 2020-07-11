all:
	cargo build

test:
	RUST_BACKTRACE=0 cargo test -- --nocapture

test1:
	RUST_BACKTRACE=1 cargo test -- --nocapture

dtest:
	RUST_BACKTRACE=0 cargo test --features debug -- --nocapture

clean:
	cargo clean

.PHONY: clean all test test1 dtest
