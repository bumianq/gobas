// Package web 嵌入 Web GUI 静态资源（编译进二进制，独立运行零依赖）。
package web

import "embed"

// Static 静态资源根（index.html / app.js / style.css）。
//
//go:embed all:static
var Static embed.FS
