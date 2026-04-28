# icons

Vendored from upstream [henrypp/simplewall](https://github.com/henrypp/simplewall) (GPL-3.0-or-later)
and [FamFamFam Silk icon set](https://famfamfam.com/lab/icons/silk/) by Mark James (CC-BY 2.5).

Two distinct license boundaries — keep them straight when redistributing:

## App icons (this directory)

| File       | Source                          | License           |
| ---------- | ------------------------------- | ----------------- |
| `100.ico`  | henrypp/simplewall `src/res/`   | GPL-3.0-or-later  |
| `101.ico`  | henrypp/simplewall `src/res/`   | GPL-3.0-or-later  |

These are upstream simplewall's own application icons. As a GPL-3.0
fork-as-port, simplewall-rs inherits the right to redistribute them
under the same license that already covers the rest of the codebase.

## Toolbar / UI glyphs (`silk/`)

Files in `silk/` are from the FamFamFam Silk icon set by Mark James.
Licensed [Creative Commons Attribution 2.5](https://creativecommons.org/licenses/by/2.5/).
Attribution is required and is provided in the repo-root `NOTICE` file.

| File                            | Used in upstream for           |
| ------------------------------- | ------------------------------ |
| `accept_button.png`             | "Enable filters" toolbar btn   |
| `arrow_refresh.png`             | Refresh                        |
| `cog_edit.png`                  | Settings                       |
| `cross.png`                     | Close / cancel                 |
| `cross_shield.png`              | Filters disabled state         |
| `delete.png`                    | Delete row                     |
| `error.png`                     | Error notification             |
| `eye.png`                       | Show packets log               |
| `note.png`                      | Notification                   |
| `page_white_delete.png`         | Clear log                      |
| `page_white_magnify.png`        | Show log                       |
| `plus.png`                      | Add app / Create rule          |
| `resultset_next.png`            | (unused upstream — kept anyway) |
| `tick_shield.png`               | Filters enabled state          |

## Deliberately not vendored

- `paypal_fulllogo.png` — PayPal's registered trademark, not GPL-clearable.
  simplewall-rs replaces upstream's "Donate" toolbar button with a
  "Releases" button that opens `github.com/amrust/simplewall-rs/releases`.
- `search_dark.png`, `search_light.png`, `search.png` — unclear origin
  in upstream (no attribution, sizes inconsistent with Silk). We'll
  generate replacements if/when M5.9 wires search-box decoration.
