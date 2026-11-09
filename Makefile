# Convenience targets. The plugin itself needs no build.

PLUGIN_LINK := $(HOME)/.idapro/plugins/rosetta.py
STATE_DIR   := $(HOME)/.idapro/plugins/ida-rosetta
PY          := python3

.PHONY: all check launcher install uninstall clean

all: check launcher

check:
	$(PY) -m py_compile \
		plugin/rosetta.py tools/ida_gdb_cfg.py \
		tests/rsp_probe.py examples/fallingwhale_helper.py

launcher:
	$(MAKE) -C launcher

install:
	@mkdir -p "$(dir $(PLUGIN_LINK))"
	ln -sfn "$(CURDIR)/plugin/rosetta.py" "$(PLUGIN_LINK)"
	@echo "installed: $(PLUGIN_LINK)"
	@echo "restart IDA, then check 'Debugger > Rosetta'"

uninstall:
	rm -f "$(PLUGIN_LINK)"
	@echo "unlinked $(PLUGIN_LINK)"
	@echo "state (safe to delete): $(STATE_DIR)"

clean:
	$(MAKE) -C launcher clean
