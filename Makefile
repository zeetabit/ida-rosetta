# Convenience targets. The plugin itself needs no build.

PLUGIN_LINK := $(HOME)/.idapro/plugins/rosetta.py
PLUGIN_SRC  := $(CURDIR)/plugin/rosetta.py
STATE_DIR   := $(HOME)/.idapro/plugins/ida-rosetta
PY          := python3
FORCE       ?= 0

.PHONY: all check check-install launcher install status uninstall clean

all: check check-install launcher

check:
	$(PY) -m py_compile \
		plugin/rosetta.py tools/ida_gdb_cfg.py tools/rosetta_headless.py \
		tests/rsp_probe.py examples/fallingwhale_helper.py \
		examples/generic_helper.py
	@if grep -RnE '^[^#]*add_bpt\(.*BPT_BRK' plugin tools examples tests 2>/dev/null; then \
		echo "error: add_bpt() type argument must be BPT_SOFT (4), not BPT_BRK (1 = BPT_WRITE)"; \
		exit 1; \
	fi

launcher:
	$(MAKE) -C launcher

install:
	@sh tools/install_plugin.sh "$(PLUGIN_SRC)" "$(PLUGIN_LINK)" "$(FORCE)"
	@echo "restart IDA, then check 'Debugger > Rosetta'"

check-install:
	@sh tests/test_install.sh

status:
	@dest="$(PLUGIN_LINK)"; \
	if [ -L "$$dest" ]; then \
		echo "symlink : $$dest -> $$(readlink "$$dest")"; \
	elif [ -e "$$dest" ]; then \
		echo "FILE    : $$dest (not a symlink)"; \
	else \
		echo "missing : $$dest"; \
	fi

uninstall:
	@dest="$(PLUGIN_LINK)"; src="$(PLUGIN_SRC)"; \
	if [ -L "$$dest" ]; then \
		cur=$$(readlink "$$dest" 2>/dev/null || true); \
		if [ "$$cur" = "$$src" ]; then \
			rm -f "$$dest"; echo "unlinked $$dest"; \
		else \
			echo "refusing: $$dest -> $$cur (not this checkout)" >&2; exit 1; \
		fi; \
	elif [ -e "$$dest" ]; then \
		echo "refusing: $$dest is not a symlink; remove it manually" >&2; exit 1; \
	else \
		echo "not installed: $$dest"; \
	fi
	@echo "state (safe to delete): $(STATE_DIR)"

clean:
	$(MAKE) -C launcher clean
