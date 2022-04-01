package ssostorage

type config struct {
	enableMultipleAccounts bool // 开启多账号，默认false
	/*
		    hashmap
			key: sso:uid:{uid}
			expiration: 最大的过期时间
			value:
				expireList:      [{"_c:parentToken","ctime"}]
				{_ct}：           存储 user 创建时间
				{_c:parentToken}: parentTokenJsonInfo
				{_c:parentToken}: parentTokenJsonInfo
	*/
	uidMapParentTokenKey string // 存储token信息的hash map
	/*
				     hashmap
					 key: sso:ptk:{parentToken}
		  			 expiration: 最大的过期时间
					 value:
						uids:                  [1,2,3]，如果是单账号，那么只有一个uid；如果是多账号，会有多个uid
						{_ct}：                 存储 parent token 创建时间
						{_u:uid}:               key名跟uid相关，存储用户登录一些信息：uid、平台、IP、UA信息，该字段可以扩展
						expireList:            [{"subTokenClientId1":"ctime"}]
						{_c:subToken}:         tokenJsonInfo
						{_c:subToken}:         tokenJsonInfo
						{_c:subToken}:         tokenJsonInfo
					 ttl: 3600
	*/
	parentTokenMapSubTokenKey string // 存储token信息的hash map
	// key token value ptoken
	/*
		hashmap
		key: sso:stk:{subToken}
		value:
			parentToken: {parentToken}
			clientId:    {subTokenClientId}
			tokenInfo:   {tokenJsonInfo}
		ttl: 3600
	*/
	subTokenMapParentTokenKey string // token与父级token的映射关系
	storeClientInfoKey        string // 存储sso client的信息
	storeAuthorizeKey         string // 存储sso authorize的信息
}

func defaultConfig() *config {
	return &config{
		enableMultipleAccounts:    false,
		uidMapParentTokenKey:      "sso:uid:%d",  // uid map parent token type
		parentTokenMapSubTokenKey: "sso:ptk:%s",  // parent token map
		subTokenMapParentTokenKey: "sso:stk:%s",  // sub token map parent token
		storeClientInfoKey:        "sso:client",  // sso的client信息，使用hash map
		storeAuthorizeKey:         "sso:auth:%s", // 存储auth信息
	}
}
