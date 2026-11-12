package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

var version = "0.2.0-dev.1"

// main запускает native интерфейс в главном потоке без Go bindings для панели.
func main() {
	dataDirectory := flag.String("data-dir", "", "Каталог профилей и доверенных SSH-ключей")
	showVersion := flag.Bool("version", false, "Показать версию desktop-клиента")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	directory := *dataDirectory
	if directory == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Не удалось определить каталог настроек пользователя.")
			os.Exit(1)
		}
		directory = filepath.Join(base, "awg_vps_control")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Не удалось определить каталог настроек приложения.")
		os.Exit(1)
	}
	app := newDesktopApp(absolute)
	mygo.App.SetName("AWG VPS Control")
	mygo.App.SetVersion(version)
	mygo.App.WhenReady(func() {
		app.window = mygo.NewWindow(mygo.WindowOptions{
			Title: "AWG VPS Control", Width: 1320, Height: 900, MinWidth: 960, MinHeight: 680,
			Content: ui.View(app.render), Page: mygo.PageOptions{DevTools: mygo.DevToolsDisabled},
		})
		app.window.OnClosed(app.shutdown)
		app.startMonitor()
	})
	mygo.App.OnBeforeQuit(func(_ *mygo.QuitEvent) { app.shutdown() })
	if err := mygo.App.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Не удалось открыть desktop-клиент AWG VPS Control.")
		os.Exit(1)
	}
}
