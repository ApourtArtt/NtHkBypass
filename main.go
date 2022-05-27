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
	/*
				Remove anticheat by adding an unconditional jump

			    00509a03 8b 45 f8        MOV        param_1,dword ptr [EBP + local_c]
		        00509a06 e8 49 fa        CALL       FUN_00509454
		                 ff ff
		        00509a0b c6 05 3c        MOV        byte ptr [DAT_006f0e3c],0x1 <---- First two bytes (0xC6, 0x05) modified for a JMP to 0x6B (+0x08, the offset) bytes later
		                 0e 6f 00 01
		        00509a12 bf dc 96        MOV        EDI,LAB_005096dc
		                 50 00
		        00509a17 8b cf           MOV        ECX=>LAB_005096dc,EDI
	*/

	addr1 := patternScan(
		data,
		[]byte("\x8B\x45\xF8\xE8\x00\x00\x00\x00\xC6\x00\x00\x00\x00\x00\x00\xBF\x00\x00\x00\x00\x8B\xCF"),
		[]byte("xxxx????x??????x????xx"),
		0x08,
	)
	patch(data, []byte("\xEB\x6B"), addr1)

	/*
				Remove anticheat error things by switching a jnz by an unconditional jump

				LAB_00509e64             XREF[1]:     00509e48(j)
		        00509e64 80 3d 3c        CMP        byte ptr [DAT_006f0e3c],0x0
		                 0e 6f 00 00
		        00509e6b 75 40           JNZ        LAB_00509ead <---- JNZ (0x75) changed to JMP (0xEB)
		        00509e6d 8d 45 f4        LEA        param_1=>local_10,[EBP + -0xc]
		        00509e70 50              PUSH       param_1

	*/

	addr2 := patternScan(
		data,
		[]byte("\x80\x3D\x3C\x0E\x6F\x00\x00\x75\x40\x8D\x45\xF4\x50"),
		[]byte("xx????xx?xxxx"),
		0x07,
	)
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
