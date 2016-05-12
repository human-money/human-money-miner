package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/bitmark-inc/go-argon2"
	"github.com/golang/protobuf/proto"
)

var argon2Ctx = &argon2.Context{
	Iterations:  1,
	Memory:      1 << 16,
	Parallelism: 2,
	HashLen:     32,
	Mode:        argon2.ModeArgon2d,
	Version:     argon2.Version13,
}

func incrementNonce(block *Block) *Block {
	block.Nonce = proto.Uint64(*block.Nonce + uint64(1))
	return block
}

func hash(block *Block) []byte {
	data, err := proto.Marshal(block)
	if err != nil {
		log.Fatal("marshaling error: ", err)
	}

	hash, err := argon2.Hash(argon2Ctx, data, data)
	if err != nil {
		log.Fatal(err)
	}

	return hash
}

func main() {
	block := &Block{
		PreviousHash: []byte{'a'},
		PublicKey:    []byte{'a'},
		Nonce:        proto.Uint64(1),
	}

	target, err := hex.DecodeString("00aad4a5aac63eeef3d466ef5fd439d1fb5fb28de7db8d05647c8a910e83a670")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", target)
	var h []byte
	for ok := true; ok; ok = (bytes.Compare(h, target) > 0) {
		h = hash(block)
		block = incrementNonce(block)
		fmt.Printf("%x\n", h)
	}
}
