# Build targets for ghp.
#
#   make release       - standard cargo release build
#   make slim          - release + non-PIE + post-process strip (stable)
#   make slim-nightly  - slim + rebuild std with panic_immediate_abort
#   make clean
#
# `slim` post-processes the binary with objcopy to drop the DWARF unwind
# tables and the exception-handling tables. Safe for us since we build
# with panic = "abort" (see Cargo.toml). Also builds as non-PIE so the
# dynamic relocation section (.rela.dyn) disappears.
#
# `slim-nightly` additionally recompiles std with our profile's
# panic = "abort", which lets LTO discard unwinding code inside std
# itself. The panic hook in src/panic.rs still runs.

CARGO ?= cargo
TARGET_TRIPLE ?= x86_64-unknown-linux-gnu
OBJCOPY ?= objcopy

NON_PIE_FLAGS := -C relocation-model=static -C link-arg=-no-pie
STRIP_SECTIONS := \
	--remove-section=.eh_frame \
	--remove-section=.eh_frame_hdr \
	--remove-section=.gcc_except_table

.PHONY: release slim slim-nightly clean size

release:
	$(CARGO) build --release

slim:
	RUSTFLAGS='$(NON_PIE_FLAGS)' $(CARGO) build --release \
		--target $(TARGET_TRIPLE)
	$(OBJCOPY) $(STRIP_SECTIONS) \
		target/$(TARGET_TRIPLE)/release/ghp \
		target/$(TARGET_TRIPLE)/release/ghp-slim

slim-nightly:
	RUSTFLAGS='$(NON_PIE_FLAGS)' \
		$(CARGO) +nightly build --release \
			--target $(TARGET_TRIPLE) \
			-Z build-std=std,panic_abort
	$(OBJCOPY) $(STRIP_SECTIONS) \
		target/$(TARGET_TRIPLE)/release/ghp \
		target/$(TARGET_TRIPLE)/release/ghp-slim

size:
	@for f in \
		target/release/ghp \
		target/$(TARGET_TRIPLE)/release/ghp \
		target/$(TARGET_TRIPLE)/release/ghp-slim; do \
		[ -f $$f ] && ls -lh $$f; \
	done

clean:
	$(CARGO) clean
