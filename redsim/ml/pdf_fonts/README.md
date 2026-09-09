# Bundled PDF faces

`DejaVuSans.ttf` and `DejaVuSans-Bold.ttf` are Unicode-range subsets of the
DejaVu Sans 2.37 faces (Bitstream Vera licence plus the DejaVu public-domain
changes; the full text is in `LICENSE`). They exist so `redsim.ml.pdf` renders
`ε`, `Δ`, `≥`, `→` and `—` in the campaign report PDF offline, in the worker
image and in CI, without system fonts.

Subset command (fonttools, from matplotlib's copy of the full faces):

    python -m fontTools.subset DejaVuSans.ttf --output-file=DejaVuSans.ttf \
      --unicodes="U+0000-024F,U+0370-03FF,U+0400-04FF,U+1E00-1EFF,U+2000-206F,U+20A0-20CF,\
    U+2100-214F,U+2190-21FF,U+2200-22FF,U+2300-23FF,U+2500-259F,U+25A0-25FF,U+2600-26FF,\
    U+2700-27BF,U+FB00-FB06,U+FFFD" --layout-features='*' --glyph-names --notdef-outline \
      --name-IDs='*' --no-hinting

Ranges: Latin (basic, supplement, extended A/B, additional), Greek, Cyrillic,
general punctuation, currency, letterlike, arrows, mathematical operators,
technical, box drawing, geometric shapes, miscellaneous symbols, dingbats,
Latin ligatures and the replacement character. A glyph outside these ranges
renders as the `.notdef` box, never as a wrong character.

`REDSIM_PDF_FONT_DIR` may point at a directory holding the full faces instead.
