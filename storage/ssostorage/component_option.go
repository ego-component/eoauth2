package ssostorage

type Option func(c *Component)

func WithUidMapParentTokenKey(key string) Option {
	return func(c *Component) {
		c.config.uidMapParentTokenKey = key
	}
}

func WithTokenMapKey(key string) Option {
	return func(c *Component) {
		c.config.parentTokenMapSubTokenKey = key
	}
}

func WithSubTokenMapParentTokenKey(key string) Option {
	return func(c *Component) {
		c.config.subTokenMapParentTokenKey = key
	}
}

func WithEnableMultipleAccounts(flag bool) Option {
	return func(c *Component) {
		c.config.enableMultipleAccounts = flag
	}
}
