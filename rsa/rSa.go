package rsa

import (
	"fmt"
	"math/big"
)

func RsA() {
	n := big.NewInt(3233)
	e := big.NewInt(17)
	d := big.NewInt(2753)

	m := big.NewInt(65)

	c := new(big.Int)
	c.Exp(m, e, n)
	fmt.Printf("加密后的密文：c: %s \n", c.String())
	de_m := new(big.Int)
	de_m.Exp(c, d, n)
	fmt.Printf("de_m: %s 字符:%c \n", de_m.String(), rune(de_m.Int64()))
}
