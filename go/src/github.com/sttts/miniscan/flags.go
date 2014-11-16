package main

import (
	"fmt"
	"strconv"
)

type uintslice []uint

func (i *uintslice) String() string {
    return fmt.Sprintf("%d", *i)
}

func (i *uintslice) Set(value string) error {
    tmp, err := strconv.Atoi(value)
    if err != nil {
        *i = append(*i, 0)
    } else {
        *i = append(*i, uint(tmp))
    }
    return nil
}
