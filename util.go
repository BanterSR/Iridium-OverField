package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"hash/crc32"
)

func RsaParsePrivKey(privKeyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privKeyPem)
	if block == nil {
		return nil, errors.New("invalid rsa private key")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func RsaDecryptPrivKey(encData []byte, privKey *rsa.PrivateKey) (decData []byte, err error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privKey, encData)
}

func crc32Hash(data []byte) uint32 {
	Hash32 := crc32.NewIEEE()
	Hash32.Write(data)
	return Hash32.Sum32()
}

var dataMap map[string][]byte

func addDataMap(key string, data []byte) {
	if dataMap == nil {
		dataMap = make(map[string][]byte)
	}
	if dataMap[key] == nil {
		dataMap[key] = make([]byte, 0)
	}
	dataMap[key] = append(dataMap[key], data...)
}

func getData(key string) []byte {
	if dataMap == nil {
		dataMap = make(map[string][]byte)
	}
	if dataMap[key] == nil {
		dataMap[key] = make([]byte, 0)
	}
	return dataMap[key]
}

func getDataMap() map[string][]byte {
	return dataMap
}

func delData(key string, len uint16) {
	if dataMap == nil {
		dataMap = make(map[string][]byte)
	}
	if dataMap[key] == nil {
		dataMap[key] = make([]byte, 0)
	}
	dataMap[key] = dataMap[key][len:]
}
