package main

import (
	"embed"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/saif/spoofer/engine"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/trayicon.png
var trayIcon []byte

func main() {
	eng := &engine.Engine{}
	deviceService := &DeviceService{Engine: eng}

	// A successful grant replaces this process, so nothing below runs twice.
	granted, grantErr := engine.EnsureNetRawCap()
	if granted {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("engine failed: %v", r)
					deviceService.SetStartupError(fmt.Sprintf("engine failed: %v", r))
				}
			}()
			go engine.Start(eng)
		}()
		fmt.Println("engine started")
	} else {
		deviceService.SetStartupError(grantErr)
	}

	// Closing the window only hides it; the engine keeps shaping traffic.
	// ShouldQuit is the single place that marks a real shutdown (tray Quit,
	// logout, signal) so the close hook can tell it apart from the X button.
	var quitting atomic.Bool

	app := application.New(application.Options{
		Name:        "fmmon",
		Description: "A network monitor and traffic shaper",
		Services: []application.Service{
			application.NewService(deviceService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		ShouldQuit: func() bool {
			quitting.Store(true)
			return true
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
		Windows: application.WindowsOptions{DisableQuitOnLastWindowClosed: true},
		Linux:   application.LinuxOptions{DisableQuitOnLastWindowClosed: true},
	})

	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "fmmon",
		Width:            1000,
		Height:           618,
		BackgroundColour: application.NewRGB(6, 7, 15),
		URL:              "/",
	})

	// Cancel the close and hide instead. The default listener that destroys
	// the window only runs when this hook lets the event through.
	win.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		if quitting.Load() {
			return
		}
		event.Cancel()
		win.Hide()
	})

	// Minimising parks the window in the tray instead of leaving a taskbar
	// entry behind. The event still happens natively; we just hide after it.
	win.RegisterHook(events.Common.WindowMinimise, func(event *application.WindowEvent) {
		if quitting.Load() {
			return
		}
		win.Hide()
	})

	showWindow := func() {
		win.UnMinimise()
		win.Show()
		win.Focus()
	}

	tray := app.SystemTray.New()
	tray.SetIcon(trayIcon)
	tray.SetTooltip("fmmon")

	menu := application.NewMenu()
	menu.Add("Show fmmon").OnClick(func(*application.Context) { showWindow() })
	menu.AddSeparator()
	menu.Add("Quit fmmon").OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(menu)

	tray.OnClick(func() {
		if win.IsVisible() {
			win.Hide()
			return
		}
		showWindow()
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
