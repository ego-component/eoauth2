package dao

import (
	"fmt"

	"gorm.io/gorm"
)

type Refresh struct {
	Id     int    `gorm:"not null;primary_key;AUTO_INCREMENT" json:"id"`    // FormID
	Token  string `gorm:"not null;default:'';comment:token" json:"token"`   // token
	Access string `gorm:"not null;default:'';comment:access" json:"access"` // access
}

func (t *Refresh) TableName() string {
	return "refresh"
}

func CreateRefreash(db *gorm.DB, data *Refresh) (err error) {
	if err = db.Create(data).Error; err != nil {
		err = fmt.Errorf("CreateRefreash, err: %w", err)
		return
	}
	return
}

// DeleteRefreshByToken Delete的扩展方法，根据Cond删除一条或多条记录。如果有delete_time则软删除，否则硬删除。
func DeleteRefreshByToken(db *gorm.DB, token string) (err error) {
	if err = db.Where("token = ?", token).Delete(&Refresh{}).Error; err != nil {
		err = fmt.Errorf("DeleteRefreshByToken, err: %w", err)
		return
	}
	return
}

// GetRefreshInfoByToken Info的扩展方法，根据Cond查询单条记录
func GetRefreshInfoByToken(db *gorm.DB, token string) (resp Refresh, err error) {
	if err = db.Where("token = ?", token).First(&resp).Error; err != nil {
		err = fmt.Errorf("GetRefreshInfoByToken, err: %w", err)
		return
	}
	return
}
