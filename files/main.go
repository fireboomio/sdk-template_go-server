package main

import (
	"custom-go/server"
)

func main() {
	/*err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}*/
	server.Execute()
}
