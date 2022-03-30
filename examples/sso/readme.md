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


## 测试单点登录方式
* 1 先使用client，使用账号、密码登录 sso server
* 2 可以看到有两个cookie： client的ego_token, sso server的ego_ptoken
* 3 这个时候我们可以干掉client的ego_token，模拟第二个client登录 sso server
* 4 因为sso server有ego_ptoken，那么这个时候第二个client点击login，就不需要输入账号、密码自动登录系统

