package templates

import "embed"

//go:embed *.xml
var files embed.FS

func Read(name string) ([]byte, error) {
	return files.ReadFile(name)
}
