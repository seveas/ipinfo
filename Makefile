ipinfo: *.go pkged.go go.mod
	go build

pkged.go: main.go templates/*
	pkger
