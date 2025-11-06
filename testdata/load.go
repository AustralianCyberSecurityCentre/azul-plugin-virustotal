package testdata

import (
	"embed"
	"log"
	"os"
	"path"
	"runtime"

	"github.com/tidwall/gjson"
)

// dir of this go module, so tests can load files beneath it
var Dir string

//go:embed data
var Data embed.FS

func WriteFileBytes(rawBytes []byte, relPath []string) error {
	endPath := path.Join(relPath...)
	fullPath := path.Join(Dir, endPath)
	err := os.WriteFile(fullPath, rawBytes, 0666)
	return err
}

func GetFileBytes(path string) []byte {
	ret, err := Data.ReadFile(path)
	if err != nil {
		log.Fatalf("could not load test file %v: %v", path, err)
	}
	return ret
}

/*Loads the file report data under data as expected by the features handlers.*/
func GetFileReportGjson(path string) gjson.Result {
	fileContents := GetFileBytes(path)
	gjsonContents := gjson.ParseBytes(fileContents)
	gjsonContents = gjsonContents.Get("data")
	return gjsonContents
}

func init() {
	_, filename, _, _ := runtime.Caller(0)
	Dir = path.Dir(filename)
}
