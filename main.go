package main

import (
	"embed"
	"fmt"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/saif/spoofer/engine"
)

//go:embed all:frontend/dist
var assets embed.FS

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
			engine.Start(eng)
		}()
	} else {
		deviceService.SetStartupError(grantErr)
	}

	app := application.New(application.Options{
		Name:        "fmmon",
		Description: "A network monitor and traffic shaper",
		Services: []application.Service{
			application.NewService(deviceService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "fmmon",
		Width:            1000,
		Height:           618,
		BackgroundColour: application.NewRGB(6, 7, 15),
		URL:              "/",
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
