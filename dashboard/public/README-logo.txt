NTRO logo drop-in
=================

To display the real NTRO logo in the dashboard header:

1. Save the official logo image here as:
       dashboard/public/ntro-logo.png
   (PNG with a transparent background works best; a square-ish crop
    around 128x128 or larger is ideal.)

2. That's it. The header (src/components/NtroLogo.tsx) automatically uses
   /ntro-logo.png when the file is present, and falls back to the built-in
   Ashoka crest + "NTRO" mark if the file is missing or fails to load.

If you prefer an SVG, save it as ntro-logo.png anyway (rasterised) OR change
REAL_LOGO_SRC in src/components/NtroLogo.tsx to '/ntro-logo.svg'.

Note: the official NTRO emblem is a government asset and is not bundled with
this project. Add it yourself from an authorised source.
