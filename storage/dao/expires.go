package dao

import (
	"fmt"

	"github.com/gotomicro/ego-component/egorm"
	"gorm.io/gorm"
)

type Expires struct {
	Id        int    `gorm:"not null;primary_key;AUTO_INCREMENT" json:"id"`            // 客户端
	Token     string `gorm:"not null;default:'';comment:token" json:"token"`           // token
	ExpiresAt int64  `gorm:"not null;default:0;comment:过期时间" json:"expiresAt"`         // 过期时间
	Ptoken    string `gorm:"not null;default:'';comment:parent token信息" json:"ptoken"` // parent token信息
}

func (t *Expires) TableName() string {
	return "expires"
}

// CreateExpires insert a new Expires into database and returns
// last inserted Id on success.
func CreateExpires(db *gorm.DB, data *Expires) (err error) {
	if err = db.Create(data).Error; err != nil {
		err = fmt.Errorf("CreateExpires, err: %w", err)
		return
	}
	return
}

// DeleteExpiresByToken Delete的扩展方法，根据Cond删除一条或多条记录。如果有delete_time则软删除，否则硬删除。
func DeleteExpiresByToken(db *gorm.DB, code string) (err error) {
	if err = db.Where("token = ?", code).Delete(&Expires{}).Error; err != nil {
		err = fmt.Errorf("DeleteExpiresByToken, err: %w", err)
		return
	}
	return
}

// GetExpireInfoByToken 根据token获取expire信息
func GetExpireInfoByToken(db *egorm.Component, token string) (resp Expires, err error) {
	if err = db.Where("token = ?", token).First(&resp).Error; err != nil {
		err = fmt.Errorf("GetExpireInfoByToken, err: %w", err)
		return
	}
	return
}
