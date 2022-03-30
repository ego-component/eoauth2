package ssostorage

import (
	"github.com/vmihailenco/msgpack"
)

// uidTokenExpire 用户Uid里parent token存储的一些信息
type uidTokenExpire struct {
	Token      string `msgpack:"t"`
	ExpireTime int64  `msgpack:"et"`
}

type uidTokenExpires []uidTokenExpire

func (u uidTokenExpires) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *uidTokenExpires) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

// clientInfo 存储客户端信息
type clientInfo struct {
	Id          string `msgpack:"id"`
	Secret      string `msgpack:"s"`
	RedirectUri string `msgpack:"r"`
}

func (u clientInfo) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *clientInfo) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type authorizeData struct {
	ClientId    string `msgpack:"id"`   // 客户端ID
	Code        string `msgpack:"code"` // Code
	Ptoken      string `msgpack:"pt"`   // Parent ParentToken
	ExpiresIn   int32  `msgpack:"ei"`   // 过期时间
	Scope       string `msgpack:"s"`    // 范围
	RedirectUri string `msgpack:"r"`    // 跳转地址
	State       string `msgpack:"s"`    // 状态
	Extra       string `msgpack:"ex"`   // 额外信息
	Ctime       int64  `msgpack:"ct"`   // 创建时间
}

func (u authorizeData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *authorizeData) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type accessData struct {
	ClientId string `msgpack:"id"` // 客户端ID
	//Authorize    string `msgpack:"au"` // Authorize
	Previous    string `msgpack:"pr"` // Parent ParentToken
	AccessToken string `msgpack:"at"` // Parent ParentToken
	//RefreshToken string `msgpack:"rt"` // Parent ParentToken
	ExpiresIn   int32  `msgpack:"ei"` // 过期时间
	Scope       string `msgpack:"s"`  // 范围
	RedirectUri string `msgpack:"r"`  // 跳转地址
	Ctime       int64  `msgpack:"ct"` // 创建时间
}

func (u accessData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *accessData) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type UidsStore []int64

func (u UidsStore) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *UidsStore) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type UidInfoStore struct {
	Platform string `msgpack:"p"`
	Ctime    int64  `msgpack:"c"`
}

func (u UidInfoStore) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *UidInfoStore) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}
