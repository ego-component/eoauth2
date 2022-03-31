package dao

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Access struct {
	Id           int    `gorm:"not null;primary_key;AUTO_INCREMENT" json:"id"`       // FormID
	Client       string `gorm:"not null;default:'';comment:客户端" json:"client"`       // client
	Authorize    string `gorm:"not null;default:'';comment:授权" json:"authorize"`     // authorize
	Previous     string `gorm:"not null;default:'';" json:"previous"`                // previous
	AccessToken  string `gorm:"not null;default:'';" json:"accessToken"`             // access_token
	RefreshToken string `gorm:"not null;default:'';" json:"refreshToken"`            // refresh_token
	ExpiresIn    int64  `gorm:"not null;default:0;comment:过期时间" json:"expiresIn"`    // expires_in
	Scope        string `gorm:"not null;default:'';comment:作用域" json:"scope"`        // scope
	RedirectUri  string `gorm:"not null;default:'';comment:跳转地址" json:"redirectUri"` // redirect_uri
	Extra        string `gorm:"not null;type:longtext;comment:额外信息" json:"extra"`    // extra
	Ctime        int64  `gorm:"not null;default:0;comment:创建时间" json:"ctime"`        // 创建时间
}

func (t *Access) TableName() string {
	return "access"
}

// CreateAccess insert a new Access into database and returns
// last inserted Id on success.
func CreateAccess(db *gorm.DB, data *Access) (err error) {
	data.Ctime = time.Now().Unix()
	if err = db.Create(data).Error; err != nil {
		err = fmt.Errorf("CreateAccess, err: %w", err)
		return
	}
	return
}

// DeleteAccessByAccessToken Delete的扩展方法，根据Cond删除一条或多条记录。如果有delete_time则软删除，否则硬删除。
func DeleteAccessByAccessToken(db *gorm.DB, accessToken string) (err error) {
	if err = db.Where("access_token = ?", accessToken).Delete(&Access{}).Error; err != nil {
		err = fmt.Errorf("DeleteAccessByAccessToken, err: %w", err)
		return
	}
	return
}

// GetAccessByAccessToken Info的扩展方法，根据Cond查询单条记录
func GetAccessByAccessToken(db *gorm.DB, accessToken string) (resp Access, err error) {
	if err = db.Where("access_token = ?", accessToken).First(&resp).Error; err != nil {
		err = fmt.Errorf("GetAccessByAccessToken, err: %w", err)
		return
	}
	return
}
