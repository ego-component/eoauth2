package model

import (
	"github.com/vmihailenco/msgpack"
)

type ParentToken struct {
	Token     Token
	Uid       int64
	StoreData ParentTokenData // 用于存储token一些信息，用来查询用户情况
}

type SubToken struct {
	Token     Token
	StoreData SubTokenData // 用于存储token一些信息，用来查询用户情况
}

type ParentTokenData struct {
	Ctime    int64  `msgpack:"c" json:"ctime"`
	UA       string `msgpack:"ua" json:"ua"`
	ClientIP string `msgpack:"ip" json:"clientIp"`
	Platform string `msgpack:"p" json:"platform"`
}

func (u ParentTokenData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *ParentTokenData) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type SubTokenData struct {
	UA       string `msgpack:"ua" json:"ua"`
	ClientIP string `msgpack:"ip" json:"clientIP"`
}

func (u SubTokenData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *SubTokenData) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}
