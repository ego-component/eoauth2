package dao

import (
	"fmt"

	"github.com/gotomicro/ego-component/egorm"
)

type App struct {
	Aid         int    `gorm:"not null;primary_key;AUTO_INCREMENT" json:"aid"`      // 应用id
	Name        string `gorm:"not null;default:'';comment:名称" json:"name"`          // 名称
	ClientId    string `gorm:"not null;default:'';comment:客户度ID" json:"clientId"`   // 客户端
	Secret      string `gorm:"not null;default:'';comment:密钥" json:"secret"`        // 秘钥
	RedirectUri string `gorm:"not null;default:'';comment:跳转地址" json:"redirectUri"` // 跳转地址
	Url         string `gorm:"not null;default:'';comment:访问地址" json:"url"`         // 访问地址
	Extra       string `gorm:"not null;type:longtext;comment:额外信息" json:"extra"`    // 额外信息
	CntCall     int    `gorm:"not null;default:'';comment:调用次数" json:"cntCall"`     // 调用次数
	State       int    `gorm:"not null;default:0;comment:状态" json:"state"`          // 状态
	Ctime       int64  `gorm:"not null;default:0;comment:创建时间" json:"ctime"`        // 创建时间
	Utime       int64  `gorm:"not null;default:0;comment:更新时间" json:"utime"`        // 更新时间
	Dtime       int64  `gorm:"not null;default:0;comment:删除时间" json:"dtime"`        // 删除时间
}

func (t *App) TableName() string {
	return "app"
}

// GetAppInfoByClientId Info的扩展方法，根据Cond查询单条记录
func GetAppInfoByClientId(db *egorm.Component, clientId string) (resp App, err error) {
	if err = db.Where("client_id = ? and dtime = 0", clientId).First(&resp).Error; err != nil {
		err = fmt.Errorf("GetAppInfoByClientId failed, err: %w", err)
		return
	}
	return
}
