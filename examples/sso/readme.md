## 初始化你的数据

```
# 1 首先你需要mysql，redis。配置好server里的redis，mysql依赖
# 2 在sso的根目录下，执行make init_data
```

## 启动服务

```
# 启动服务
make run_server
# 启动客户端
make run_client
```

## 访问

* 1 浏览器里访问`http://localhost:29001`
* 2 点击Login
* 3 输入用户名、密码: askuy、123456
* 4 登录成功后，会跳到`http://localhost:29001`，这个时候你就可以看到用户名和`token`。
* 5 你可以`refresh token`，然后在刷新页面，可以看到变换的`token`
* 6 也可以退出登录，在访问`http://localhost:29001`，那么你就又进入到登录页面
