package ssostorage

type Option func(c *Storage)

func WithUidMapParentTokenKey(key string) Option {
	return func(c *Storage) {
		c.config.uidMapParentTokenKey = key
	}
}

func WithTokenMapKey(key string) Option {
	return func(c *Storage) {
		c.config.parentTokenMapSubTokenKey = key
	}
}

func WithSubTokenMapParentTokenKey(key string) Option {
	return func(c *Storage) {
		c.config.subTokenMapParentTokenKey = key
	}
}

func WithEnableMultipleAccounts(flag bool) Option {
	return func(c *Storage) {
		c.config.enableMultipleAccounts = flag
	}
}
