package techfp

import _ "embed"

// The Wappalyzer fingerprint database, shipped unmodified under its MIT license
// (see wappalyzer/LICENSE.md). It is embedded data, not a Go dependency, so it
// adds nothing to the module graph or the plugin ABI — the reason the library
// itself (which now pulls a headless-browser tree) is not imported.
//
//go:embed wappalyzer/fingerprints_data.json
var fingerprintsJSON []byte

//go:embed wappalyzer/categories_data.json
var categoriesJSON []byte
