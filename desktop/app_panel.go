package main

import (
	"errors"
	"net/url"

	"github.com/egoist/mygo"
	"github.com/khorevaa/awg-vps-control/desktop/internal/connection"
)

// panelURLAllowed разрешает навигацию только в точном origin текущего локального туннеля.
func panelURLAllowed(raw, origin string) bool {
	parsed, err := url.Parse(raw)
	base, baseError := url.Parse(origin)
	return err == nil && baseError == nil && parsed.User == nil && parsed.Opaque == "" && parsed.Scheme == base.Scheme && parsed.Host == base.Host
}

// openPanel создаёт пустой изолированный WebView, настраивает запреты и лишь затем открывает VPS.
func (app *DesktopApp) openPanel(connected *connection.Connection) error {
	origin := connected.URL()
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" || parsed.Opaque != "" {
		return errors.New("туннель вернул некорректный адрес панели")
	}
	view, err := app.window.NewWebView(mygo.WebViewOptions{
		URL: "about:blank", Page: mygo.PageOptions{
			Untrusted: true, Session: mygo.NewEphemeralSession(), DevTools: mygo.DevToolsDisabled,
		},
	})
	if err != nil {
		return errors.New("WebView недоступен; проверьте наличие Microsoft Edge WebView2 Runtime")
	}
	page := view.Page()
	page.OnWillNavigate(func(event *mygo.NavigateEvent) {
		if !panelURLAllowed(event.URL, origin) {
			event.PreventDefault()
		}
	})
	page.SetWindowOpenHandler(func(_ mygo.WindowOpenRequest) *mygo.WindowOptions { return nil })
	page.OnWillDownload(func(event *mygo.DownloadEvent) { event.PreventDefault() })
	page.SetPermissionHandler(func(_ mygo.PermissionRequest) bool { return false })
	if err := page.LoadURL(origin); err != nil {
		view.Destroy()
		return errors.New("не удалось открыть адрес подключённой панели")
	}
	app.webView = view
	return nil
}
