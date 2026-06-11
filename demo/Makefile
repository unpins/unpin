# Regenerate the unpin demo animations (dark + light) from demo.cast.
#
#   make            render both SVGs from the committed demo.cast (offline, fast)
#   make record     re-record demo.cast by running unpin for real (needs network)
#   make clean      remove the generated SVGs
#
# Recording and rendering are split on purpose: `render` is deterministic and
# offline, so the SVGs always regenerate from the cast the same way. Only
# `record` touches the network (it actually downloads packages). termtosvg's
# diff model keeps each SVG ~200 KB raw / ~20 KB gzipped, and the window
# decoration (rounded frame + traffic lights) comes from the theme templates.

TERMTOSVG ?= $(shell nix build nixpkgs#termtosvg --no-link --print-out-paths)/bin/termtosvg
MAXFRAME  ?= 1400          # cap idle frames (ms) so long pauses don't drag the loop
THEMES    := dark light
SVGS      := $(THEMES:%=unpin-demo-%.svg)

.PHONY: all record clean
all: $(SVGS)

# Render one theme: re-themes the single cast via the template's CSS palette,
# so dark and light share identical timing.
unpin-demo-%.svg: demo.cast templates/unpins-%.svg
	$(TERMTOSVG) render $< $@ -t templates/unpins-$*.svg -M $(MAXFRAME)

record:
	TERMTOSVG='$(TERMTOSVG)' python3 demo.py record
	$(MAKE) all

clean:
	rm -f $(SVGS)
