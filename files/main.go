package main

import (
	"custom-go/server"
	_ "github.com/golang/geo/s2"
	_ "github.com/joho/godotenv"
	_ "github.com/shopspring/decimal"
	// 根据需求，开启注释
	//_ "custom-go/customize"
	//_ "custom-go/function"
	//_ "custom-go/proxy"
)

func main() {
	server.Execute()
}
