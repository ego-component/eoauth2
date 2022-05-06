package ssostorage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ego-component/eoauth2/server/model"
	"github.com/ego-component/eredis"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/cast"
)

type userToken struct {
	config              *config
	redis               *eredis.Component
	fieldCtime          string
	fieldExpireTimeList string
	fieldClient         string // ClientInfo 存储的parent token
}

func newUidMapParentToken(config *config, redis *eredis.Component) *userToken {
	return &userToken{
		config:              config,
		redis:               redis,
		fieldCtime:          "_ct",  // expire time List
		fieldExpireTimeList: "_etl", // expire time List
		fieldClient:         "_c:",   // ClientInfo 存储的parent token

	}
}

func (u *userToken) getKey(uid int64) string {
	return fmt.Sprintf(u.config.uidMapParentTokenKey, uid)
}

func (u *userToken) getFieldKey(parentToken string) string {
	return u.fieldClient + parentToken
}

// 并发操作redis情况不考虑，因为一个用户使用多个终端，并发登录极其少见
// 1 先取出这个key里面的数据
//   expireTimeList:            [{"clientType1|parentToken":"expire的时间戳"}]
//	 expireTime:                最大过期时间
func (u *userToken) setToken(ctx context.Context, uid int64, pToken model.Token) error {
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
		Field:      fieldKey,
		ExpireTime: nowTime + pToken.ExpiresIn,
	})

	// 删除过期的数据
	hdelFields := make([]string, 0)
	for _, value := range expireTimeList {
		// 过期时间小于当前时间，那么需要删除
		if value.ExpireTime <= nowTime {
			hdelFields = append(hdelFields, value.Field)
			continue
		}
		newExpireTimeList = append(newExpireTimeList, value)
	}
	if len(hdelFields) > 0 {
		err = u.redis.HDel(ctx, u.getKey(uid), hdelFields...)
		if err != nil {
			return fmt.Errorf("userToken setToken HDel expire data failed, error: %w", err)
		}
	}

	err = u.redis.HSet(ctx, u.getKey(uid), u.fieldExpireTimeList, newExpireTimeList.Marshal())
	if err != nil {
		return fmt.Errorf("userToken setToken HSet expire time failed, error: %w", err)
	}

	// 将parent token信息存入
	pTokenByte, err := pToken.Marshal()
	if err != nil {
		return fmt.Errorf("userToken.createToken failed, err: %w", err)
	}

	err = u.redis.HSet(ctx, u.getKey(uid), u.getFieldKey(pToken.Token), pTokenByte)
	if err != nil {
		return fmt.Errorf("userToken setToken HSet token info failed, error: %w", err)
	}

	// 如果之前没数据，那么expireTime为0，所以会写入
	// 新的token大于，之前的过期时间，所以需要续期
	if pToken.ExpiresIn > expireTime {
		err = u.redis.Client().Expire(ctx, u.getKey(uid), time.Duration(pToken.ExpiresIn)*time.Second).Err()
		if err != nil {
			return fmt.Errorf("userToken setToken expire error %w", err)
		}
	}

	if flagCreate {
		err = u.redis.HSet(ctx, u.getKey(uid), u.fieldCtime, time.Now().Unix())
		if err != nil {
			return fmt.Errorf("userToken setToken HSet create time failed, error: %w", err)
		}
	}

	return nil
}

func (u *userToken) removeParentToken(ctx context.Context, uid int64, parentToken string) error {
	_ = u.redis.HDel(ctx, u.getKey(uid), u.getFieldKey(parentToken))
	expireTimeList, err := u.getExpireTimeList(ctx, uid)
	if err != nil {
		return err
	}

	newExpireTimeList := make(UserTokenExpires, 0)
	// 删除不要的数据
	for _, value := range expireTimeList {
		if value.Field == u.getFieldKey(parentToken) {
			continue
		}
		newExpireTimeList = append(newExpireTimeList, value)
	}
	err = u.redis.HSet(ctx, u.getKey(uid), u.fieldExpireTimeList, newExpireTimeList.Marshal())
	if err != nil {
		return fmt.Errorf("parentToken removeSubToken failed, error: %w", err)
	}
	return nil
}

// 获取过期时间，最新的在最前面。
func (u *userToken) getExpireTimeList(ctx context.Context, uid int64) (userInfo UserTokenExpires, err error) {
	// 根据父节点token，获取用户信息
	infoBytes, err := u.redis.Client().HGet(ctx, u.getKey(uid), u.fieldExpireTimeList).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		err = fmt.Errorf("userToken getExpireTimeList failed, err: %w", err)
		return
	}
	if errors.Is(err, redis.Nil) {
		err = nil
		return
	}

	pUserInfo := &userInfo
	err = pUserInfo.Unmarshal(infoBytes)
	if err != nil {
		err = fmt.Errorf("userToken getExpireTimeList json unmarshal error, %w", err)
		return
	}
	return
}

// 获取过期时间，快过期的在最前面。
func (u *userToken) getExpireTime(ctx context.Context, uid int64) (output int64, err error) {
	// 根据父节点token，获取用户信息
	expireTime, err := u.redis.Client().TTL(ctx, u.getKey(uid)).Result()
	if err != nil {
		err = fmt.Errorf("userToken getExpireTime failed, err: %w", err)
		return
	}
	output = expireTime.Milliseconds() / 1000
	return
}

func (p *userToken) getAll(ctx context.Context, uid int64) (output *UserStore, err error) {
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
		p.processData(output, key, value)
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

func (p *userToken) processData(store *UserStore, key string, value string) {
	switch true {
	case key == p.fieldCtime:
		store.Ctime = cast.ToInt64(value)
	case key == p.fieldExpireTimeList:
		store.ExpireTimeList.Unmarshal([]byte(value))
	case strings.HasPrefix(key, p.fieldClient):
		arr := strings.Split(key, ":")
		if len(arr) != 2 {
			return
		}
		data := &model.Token{}
		err := data.Unmarshal([]byte(value))
		if err != nil {
			return
		}
		store.Clients[arr[1]] = data
	}
}
