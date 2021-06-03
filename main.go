package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

func patternScan(data, needle, mask []byte, offset int) int {
	for i := 0; i < len(data)-len(needle)-offset; i++ {
		j := 0
		for ; j < len(needle); j++ {
			if data[i+j] != needle[j] && mask[j] == 'x' {
				break
			}
		}
		if j == len(needle) {
			return i + offset
		}
	}
	return -1
}

func patch(original, patch []byte, address int) []byte {
	output := original
	copy(output[address:address+len(patch)], patch)
	return output
}

func process(data []byte) []byte {
	addr1 := patternScan(
		data,
		[]byte("\x8B\x45\xF8\xE8\x00\x00\x00\x00\xC6\x45\xE3\x01\xBF\x00\x00\x00\x00\x8B\xCF"),
		[]byte("xxxx????xxxxx????xx"),
		0x08,
	)

	addr2 := patternScan(
		data,
		[]byte("\x80\x7D\xE3\x00\x75\x00\x8D\x45\xF4\x50"),
		[]byte("xxxxx?xxxx"),
		0x04,
	)

	patch(data, []byte("\xEB\x65"), addr1)
	patch(data, []byte("\xEB"), addr2)

	return data
}

func main() {
	var path string
	if len(os.Args) < 2 {
		var err error
		path, err = os.Getwd()
		if err != nil {
			panic(err)
		}
		path = filepath.Join(path, "NostaleX.dat")
	} else {
		path = os.Args[1]
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	data = process(data)

	ioutil.WriteFile("Bypass.dat", data, 0777)
}
