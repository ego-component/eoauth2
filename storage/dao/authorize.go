package dao

import (
	"fmt"
	"time"

	"github.com/gotomicro/ego-component/egorm"
	"gorm.io/gorm"
)

type Authorize struct {
	Id          int    `gorm:"not null;primary_key;AUTO_INCREMENT" json:"id"`       // FormID
	Client      string `gorm:"not null;default:'';comment:客户端" json:"client"`       // 客户端
	Code        string `gorm:"not null;default:'';comment:CODE码" json:"code"`       // CODE码
	ExpiresIn   int64  `gorm:"not null;default:0;comment:过期时间" json:"expiresIn"`    // 过期时间
	Scope       string `gorm:"not null;default:'';comment:范围" json:"scope"`         // 范围
	RedirectUri string `gorm:"not null;default:'';comment:跳转地址" json:"redirectUri"` // 跳转地址
	State       string `gorm:"not null;default:'';comment:状态" json:"state"`         // state信息，来自于url上的state信息
	Extra       string `gorm:"not null;type:longtext;comment:额外信息" json:"extra"`    // 额外信息
	Ctime       int64  `gorm:"not null;default:0;comment:创建时间" json:"ctime"`        // 创建时间
}

func (t *Authorize) TableName() string {
	return "authorize"
}

// CreateAuthorize insert a new Authorize into database and returns
// last inserted Id on success.
func CreateAuthorize(db *gorm.DB, data *Authorize) (err error) {
	data.Ctime = time.Now().Unix()
	if err = db.Create(data).Error; err != nil {
		err = fmt.Errorf("CreateAuthorize, err: %w", err)
		return
	}
	return
}

func DeleteAuthorizeByCode(db *gorm.DB, code string) (err error) {
	if err = db.Where("code = ?", code).Delete(&Authorize{}).Error; err != nil {
		err = fmt.Errorf("DeleteAuthorizeByCode, err: %w", err)
		return
	}

	return
}

// GetAuthorizeInfoByCode Info的扩展方法，根据Cond查询单条记录
func GetAuthorizeInfoByCode(db *egorm.Component, code string) (resp Authorize, err error) {
	if err = db.Where("code = ?", code).First(&resp).Error; err != nil {
		err = fmt.Errorf("GetAuthorizeInfoByCode, err: %w", err)
		return
	}
	return
}
