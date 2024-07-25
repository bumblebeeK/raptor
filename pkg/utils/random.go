package utils

import (
	"math/rand"
	"time"
)

const CharSet = "abcdefghijklmnopqrstuvwxyz0123456789"

func RandomString(length int) string {
	rand.Seed(time.Now().UnixNano())

	b := make([]byte, length)
	for i := range b {
		b[i] = CharSet[rand.Intn(len(CharSet))]
	}
	return string(b)
}
