package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    // 创建一个默认的 Gin 路由器
    router := gin.Default()

    // 定义一个 GET 请求处理，返回 JSON 格式的问候消息
    router.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "Hello, world!",
        })
    })

    // 让服务器监听在 8080 端口
    router.Run(":8080")
}
