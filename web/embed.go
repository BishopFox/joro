package web

import "embed"

//go:embed dist
var Dist embed.FS

//go:embed src/themes
var Themes embed.FS
