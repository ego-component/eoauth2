package ssostorage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ego-component/eoauth2/server/model"
	"github.com/go-redis/redis/v8"
	"github.com/gotomicro/ego-component/eredis"
	"github.com/spf13/cast"
)

type uidMapParentToken struct {
	config                    *config
	redis                     *eredis.Component
	hashCtime                 string
	hashExpireTimeList        string
	uidMapParentTokenFieldKey string // 存储token信息的hash map的field key  {clientType1|parentToken}
}

func newUidMapParentToken(config *config, redis *eredis.Component) *uidMapParentToken {
	return &uidMapParentToken{
		config:                    config,
		redis:                     redis,
		hashCtime:                 "_ct",   // expire time List
		hashExpireTimeList:        "_etl",  // expire time List
		uidMapParentTokenFieldKey: "_c:%s", // uid map parent token type

	}
}

func (u *uidMapParentToken) getKey(uid int64) string {
	return fmt.Sprintf(u.config.uidMapParentTokenKey, uid)
}

func (u *uidMapParentToken) getFieldKey(parentToken string) string {
	return fmt.Sprintf(u.uidMapParentTokenFieldKey, parentToken)
}

// 并发操作redis情况不考虑，因为一个用户使用多个终端，并发登录极其少见
// 1 先取出这个key里面的数据
//   expireTimeList:            [{"clientType1|parentToken":"expire的时间戳"}]
//	 expireTime:                最大过期时间
func (u *uidMapParentToken) setToken(ctx context.Context, uid int64, platform string, pToken model.Token) error {
	fieldKey := u.getFieldKey(pToken.Token)
	var flagCreate bool
	expireTime, err := u.getExpireTime(ctx, uid)
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}

	// 如果不存在，那么需要创建
	if errors.Is(err, redis.Nil) {
		flagCreate = true
		err = nil
	}

	expireTimeList, err := u.getExpireTimeList(ctx, uid)
	if err != nil {
		return err
	}

	nowTime := time.Now().Unix()
	newExpireTimeList := make(UserTokenExpires, 0)
	// 新数据添加到队列前面，这样方便后续清除数据，或者对数据做一些限制
	newExpireTimeList = append(newExpireTimeList, UserTokenExpire{
		Token:      fieldKey,
		ExpireTime: nowTime + pToken.ExpiresIn,
	})

	// 删除过期的数据
	hdelFields := make([]string, 0)
	for _, value := range expireTimeList {
		// 过期时间小于当前时间，那么需要删除
		if value.ExpireTime <= nowTime {
			hdelFields = append(hdelFields, value.Token)
			continue
		}
		newExpireTimeList = append(newExpireTimeList, value)
	}
	if len(hdelFields) > 0 {
		err = u.redis.HDel(ctx, u.getKey(uid), hdelFields...)
		if err != nil {
			return fmt.Errorf("uidMapParentToken setToken HDel expire data failed, error: %w", err)
		}
	}

	err = u.redis.HSet(ctx, u.getKey(uid), u.hashExpireTimeList, newExpireTimeList.Marshal())
	if err != nil {
		return fmt.Errorf("uidMapParentToken setToken HSet expire time failed, error: %w", err)
	}

	// 将parent token信息存入
	pTokenByte, err := pToken.Marshal()
	if err != nil {
		return fmt.Errorf("uidMapParentToken.createToken failed, err: %w", err)
	}

	err = u.redis.HSet(ctx, u.getKey(uid), u.getFieldKey(pToken.Token), pTokenByte)
	if err != nil {
		return fmt.Errorf("uidMapParentToken setToken HSet token info failed, error: %w", err)
	}

	// 如果之前没数据，那么expireTime为0，所以会写入
	// 新的token大于，之前的过期时间，所以需要续期
	if pToken.ExpiresIn > expireTime {
		err = u.redis.Client().Expire(ctx, u.getKey(uid), time.Duration(pToken.ExpiresIn)*time.Second).Err()
		if err != nil {
			return fmt.Errorf("uidMapParentToken setToken expire error %w", err)
		}
	}

	if flagCreate {
		err = u.redis.HSet(ctx, u.getKey(uid), u.hashCtime, time.Now().Unix())
		if err != nil {
			return fmt.Errorf("uidMapParentToken setToken HSet create time failed, error: %w", err)
		}
	}

	return nil
}

// 获取过期时间，最新的在最前面。
func (u *uidMapParentToken) getExpireTimeList(ctx context.Context, uid int64) (userInfo UserTokenExpires, err error) {
	// 根据父节点token，获取用户信息
	infoBytes, err := u.redis.Client().HGet(ctx, u.getKey(uid), u.hashExpireTimeList).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		err = fmt.Errorf("uidMapParentToken getExpireTimeList failed, err: %w", err)
		return
	}
	if errors.Is(err, redis.Nil) {
		err = nil
		return
	}

	pUserInfo := &userInfo
	err = pUserInfo.Unmarshal(infoBytes)
	if err != nil {
		err = fmt.Errorf("uidMapParentToken getExpireTimeList json unmarshal error, %w", err)
		return
	}
	return
}

// 获取过期时间，快过期的在最前面。
func (u *uidMapParentToken) getExpireTime(ctx context.Context, uid int64) (output int64, err error) {
	// 根据父节点token，获取用户信息
	expireTime, err := u.redis.Client().TTL(ctx, u.getKey(uid)).Result()
	if err != nil {
		err = fmt.Errorf("uidMapParentToken getExpireTime failed, err: %w", err)
		return
	}
	output = expireTime.Milliseconds() / 1000
	return
}

func (p *uidMapParentToken) getAll(ctx context.Context, uid int64) (output *UserStore, err error) {
	allInfo, err := p.redis.Client().HGetAll(ctx, p.getKey(uid)).Result()
	if err != nil {
		err = fmt.Errorf("tokgen get redis hmget string error, %w", err)
		return
	}
	output = &UserStore{
		Ctime:          0,
		Clients:        make(map[string]*model.Token),
		ExpireTimeList: &UserTokenExpires{},
	}
	for key, value := range allInfo {
		output.processData(key, value)
	}
	ttl, err := p.redis.Client().TTL(ctx, p.getKey(uid)).Result()
	if err != nil {
		err = fmt.Errorf("parentToken getAll failed,err: %w", err)
		return
	}
	output.TTL = ttl.Milliseconds() / 1000
	return
}

// UserStore 存储的所有信息
type UserStore struct {
	Ctime          int64                   `json:"ctime"`
	Clients        map[string]*model.Token `json:"clients"`
	ExpireTimeList *UserTokenExpires       `json:"expireTimeList"`
	TTL            int64                   `json:"ttl"`
}

func (p *UserStore) processData(key string, value string) {
	switch true {
	case key == "_ct":
		p.Ctime = cast.ToInt64(value)
	case key == "_etl":
		p.ExpireTimeList.Unmarshal([]byte(value))
	case strings.HasPrefix(key, "_c:"):
		arr := strings.Split(key, ":")
		if len(arr) != 2 {
			return
		}
		data := &model.Token{}
		err := data.Unmarshal([]byte(value))
		if err != nil {
			return
		}
		p.Clients[arr[1]] = data
	}
}
