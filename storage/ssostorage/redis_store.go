package ssostorage

import (
	"github.com/vmihailenco/msgpack"
)

// UserTokenExpire 用户Uid里parent token存储的一些信息
type UserTokenExpire struct {
	Field      string `msgpack:"f" json:"field"`
	ExpireTime int64  `msgpack:"et" json:"expireTime"`
}

type UserTokenExpires []UserTokenExpire

func (u UserTokenExpires) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *UserTokenExpires) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

// ClientInfo 存储客户端信息
type ClientInfo struct {
	ClientId    string `msgpack:"id" json:"clientId"`
	Secret      string `msgpack:"s" json:"secret"`
	RedirectUri string `msgpack:"r" json:"redirectUri"`
}

func (u ClientInfo) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *ClientInfo) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type authorizeData struct {
	ClientId    string `msgpack:"id"`   // 客户端ID
	Code        string `msgpack:"code"` // Code
	Ptoken      string `msgpack:"pt"`   // Parent ParentToken
	ExpiresIn   int64  `msgpack:"ei"`   // 过期时间
	Scope       string `msgpack:"s"`    // 范围
	RedirectUri string `msgpack:"r"`    // 跳转地址
	State       string `msgpack:"s"`    // 状态
	Ctime       int64  `msgpack:"ct"`   // 创建时间
}

func (u authorizeData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *authorizeData) Unmarshal(content []byte) error {
	return msgpack.Unmarshal(content, u)
}

type AccessData struct {
	ClientId      string `msgpack:"id" json:"clientId"`        // 客户端ID
	PreviousToken string `msgpack:"pret" json:"previousToken"` // 上一个Token信息
	CurrentToken  string `msgpack:"curt" json:"currentToken"`  // 当前Token信息，这个用于刷新token使用
	ExpiresIn     int64  `msgpack:"ei" json:"expiresIn"`       // 过期时间
	Scope         string `msgpack:"s" json:"scope"`            // 范围
	RedirectUri   string `msgpack:"r" json:"redirectUri"`      // 跳转地址
	Ctime         int64  `msgpack:"ct" json:"ctime"`           // 创建时间
}

func (u AccessData) Marshal() []byte {
	info, _ := msgpack.Marshal(u)
	return info
}

func (u *AccessData) Unmarshal(content []byte) error {
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
