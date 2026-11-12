package main

import (
	"context"
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

// panelAttemptCurrent проверяет попытку после native вызовов, обрабатывающих вложенные события окна.
func (app *DesktopApp) panelAttemptCurrent(ctx context.Context, connected *connection.Connection, generation uint64) bool {
	if app.closed || app.generation != generation || ctx.Err() != nil {
		return false
	}
	select {
	case <-connected.Done():
		return false
	default:
		return true
	}
}

// openPanel устанавливает разовую cookie в изолированную сессию до открытия авторизованной панели.
func (app *DesktopApp) openPanel(ctx context.Context, connected *connection.Connection, generation uint64) error {
	if !app.panelAttemptCurrent(ctx, connected, generation) {
		return errors.New("попытка подключения уже завершена")
	}
	origin := connected.URL()
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" || parsed.Opaque != "" {
		return errors.New("туннель вернул некорректный адрес панели")
	}
	session := mygo.NewEphemeralSession()
	cookie, err := connected.TakePanelCookie()
	if err != nil || cookie == nil {
		return errors.New("разовая авторизация панели недоступна; подключитесь заново")
	}
	defer func() {
		cookie.Value, cookie.Raw = "", ""
	}()
	var view *mygo.WebView
	ready, cookieAttempted := false, false
	defer func() {
		if !ready && view != nil {
			if cookieAttempted && !view.IsDestroyed() {
				// Destroy ниже удалит всё ephemeral-хранилище даже при отказе очистки cookie.
				_ = session.Cookies.Clear()
			}
			view.Destroy()
		}
	}()
	view, err = app.window.NewWebView(mygo.WebViewOptions{
		URL: "about:blank", Page: mygo.PageOptions{
			Untrusted: true, Session: session, DevTools: mygo.DevToolsDisabled,
		},
	})
	if !app.panelAttemptCurrent(ctx, connected, generation) {
		return errors.New("попытка подключения уже завершена")
	}
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
	nativeCookie := mygo.Cookie{
		Name: cookie.Name, Value: cookie.Value, Domain: parsed.Hostname(), Path: "/",
		Secure: true, HTTPOnly: true, SameSite: mygo.CookieSameSiteStrict, Expires: cookie.Expires,
	}
	cookieAttempted = true
	err = session.Cookies.Set(nativeCookie)
	nativeCookie.Value, cookie.Value, cookie.Raw = "", "", ""
	if !app.panelAttemptCurrent(ctx, connected, generation) || view.IsDestroyed() {
		return errors.New("попытка подключения уже завершена")
	}
	if err != nil {
		return errors.New("не удалось авторизовать встроенную панель; подключитесь заново")
	}
	if err := page.LoadURL(origin); err != nil {
		return errors.New("не удалось открыть адрес подключённой панели")
	}
	if !app.panelAttemptCurrent(ctx, connected, generation) || view.IsDestroyed() {
		return errors.New("попытка подключения уже завершена")
	}
	app.webView = view
	ready = true
	return nil
}
