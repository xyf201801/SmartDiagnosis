package main

import (
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// User 模型，用来存储用户数据
type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique"`
	Password  string
	CreatedAt time.Time
}

var db *gorm.DB

// initDB 用来初始化数据库连接和自动建表
func initDB() {
	// 修改下行中的 DSN（数据源名称），确保和你的 PostgreSQL 配置一致
	dsn := "host=localhost user=postgres password=xyf2025 dbname=smartdiagnosis port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("数据库连接失败: ", err)
	}
	// 自动迁移，创建或更新表结构
	db.AutoMigrate(&User{})
}
