package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// generateRandomKey 生成指定字节数的随机密钥，并转换为十六进制字符串
func generateRandomKey(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

var jwtKey []byte

// User 模型
type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique"`
	Password  string
	CreatedAt time.Time
}

// DiagnosisRecord 问诊记录模型
type DiagnosisRecord struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      // 关联用户
	Query     string    // 用户提问
	Response  string    // AI 回答
	CreatedAt time.Time // 记录创建时间
}

var db *gorm.DB

// 初始化数据库
func initDB() {
	dsn := "host=localhost user=postgres password=xyf2025 dbname=smartdiagnosis port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("数据库连接失败: ", err)
	}
	db.AutoMigrate(&User{}, &DiagnosisRecord{})
}

// Credentials 用于接收用户注册和登录时的请求数据
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// DiagnosisRequest 用于问诊请求的数据格式
type DiagnosisRequest struct {
	Query string `json:"query"`
}

func init() {
	// 从环境变量中获取 JWT_SECRET
	key := os.Getenv("JWT_SECRET")
	// 如果环境变量中没有设置，则生成一个随机密钥
	if key == "" {
		bytes := make([]byte, 32) // 生成32字节的随机数据
		if _, err := rand.Read(bytes); err != nil {
			fmt.Println("生成随机密钥失败:", err)
			os.Exit(1)
		}
		key = hex.EncodeToString(bytes)
		// 这里可以选择把生成的密钥打印出来，便于后续持久化保存
		fmt.Println("生成新的 JWT_SECRET:", key)
		// 注意：通过 os.Setenv 设置的环境变量仅对当前进程有效
		os.Setenv("JWT_SECRET", key)
	}
	// 将密钥转换成 []byte 类型，并赋值给全局变量 jwtKey
	jwtKey = []byte(key)
}

func main() {

	// 初始化数据库
	initDB()

	// 创建 Gin 路由器
	router := gin.Default()

	// 定义注册和登录路由
	router.POST("/register", register)
	router.POST("/login", login)

	// 创建一个需要认证的路由组
	authorized := router.Group("/")
	authorized.Use(AuthMiddleware())
	{
		// 问诊接口
		authorized.POST("/diagnosis", diagnosis)
		// 后续可增加 GET 接口来获取用户的历史问诊记录
	}

	// 启动服务器监听 8080 端口
	router.Run(":8080")
}

// register 处理用户注册
func register(c *gin.Context) {
	var creds Credentials
	// 绑定 JSON 请求体到结构体
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求数据不正确"})
		return
	}

	// 对密码进行哈希处理
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码处理出错"})
		return
	}

	// 创建用户对象
	user := User{
		Username: creds.Username,
		Password: string(hashedPassword),
	}

	// 保存到数据库
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户注册失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "注册成功"})
}

// login 处理用户登录
func login(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求数据不正确"})
		return
	}

	var user User
	// 在数据库中查找用户
	if err := db.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户不存在"})
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}

	// 创建 JWT token，设置 24 小时有效期
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Subject:   creds.Username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// AuthMiddleware 是一个简单的 JWT 认证中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少token"})
			c.Abort()
			return
		}
		// 期望格式为 "Bearer <token>"
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenStr, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token"})
			c.Abort()
			return
		}
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
			c.Set("username", claims.Subject)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token claims"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// diagnosis 处理问诊请求
func diagnosis(c *gin.Context) {
	var req DiagnosisRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求数据不正确"})
		return
	}
	// 从上下文中获取用户名
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证用户"})
		return
	}
	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户不存在"})
		return
	}
	// 模拟调用 ChatGPT API，这里后续可以替换为真实的 API 调用
	diagnosisResponse := callChatGPT(req.Query)
	// 创建问诊记录
	record := DiagnosisRecord{
		UserID:    user.ID,
		Query:     req.Query,
		Response:  diagnosisResponse,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&record).Error; err != nil {
		log.Println("保存记录错误：", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "记录保存失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":   "诊断成功",
		"diagnosis": diagnosisResponse,
		"record_id": record.ID,
	})
}

// callChatGPT 模拟调用 ChatGPT 接口，后续可以替换为实际的 API 调用
func callChatGPT(query string) string {
	// 这里返回一个模拟诊断结果
	return "初步诊断结果：您可能需要进一步检查。"
}
