# Regenerate the unpin demo animations (dark + light) from demo.cast.
#
#   make            render both SVGs from the committed demo.cast (offline, fast)
#   make record     re-record demo.cast by running unpin for real (needs network)
#   make publish    copy the rendered SVGs into the website repo (the served copy)
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

# Where the served copies live. These SVGs are gitignored here on purpose —
# the website repo (sibling checkout) is what deploys them to unpins.org/demo/.
WEBSITE_DEMO ?= ../../website/demo

.PHONY: all record publish clean
all: $(SVGS)

# Render one theme: re-themes the single cast via the template's CSS palette,
# so dark and light share identical timing.
unpin-demo-%.svg: demo.cast templates/unpins-%.svg
	$(TERMTOSVG) render $< $@ -t templates/unpins-$*.svg -M $(MAXFRAME)

record:
	TERMTOSVG='$(TERMTOSVG)' python3 demo.py record
	$(MAKE) all

# Copy the rendered SVGs into the website repo, which serves and deploys them.
# Commit them over there — they're gitignored in this repo.
publish: all
	cp $(SVGS) $(WEBSITE_DEMO)/

clean:
	rm -f $(SVGS)
