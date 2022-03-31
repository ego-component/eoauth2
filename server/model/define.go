package model

import (
	"github.com/vmihailenco/msgpack"
)

type ParentToken struct {
	Token     Token
	StoreData ParentTokenData // 用于存储token一些信息，用来查询用户情况
}

type SubToken struct {
	Token     Token
	StoreData SubTokenData // 用于存储token一些信息，用来查询用户情况
}

type ParentTokenData struct {
	Uid      int64  `msgpack:"uid"`
	UA       string `msgpack:"ua"`
	ClientIP string `msgpack:"ip"`
	Platform string `msgpack:"p"`
}

func (u ParentTokenData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *ParentTokenData) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type SubTokenData struct {
	UA       string `msgpack:"ua"`
	ClientIP string `msgpack:"ip"`
}

func (u SubTokenData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *SubTokenData) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}
