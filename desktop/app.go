package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/khorevaa/awg-vps-control/desktop/internal/connection"
)

// DesktopApp хранит состояние native интерфейса исключительно в главном потоке.
type DesktopApp struct {
	window         *mygo.Window                       // Окно MyGo с native формой и встроенной панелью.
	directory      string                             // Каталог несекретных профилей и known_hosts.
	profiles       []connection.SSHProfile            // Сохранённые подключения без паролей.
	profilesLoaded bool                               // Исходный файл прочитан; ошибочное состояние нельзя перезаписывать.
	draft          connection.SSHProfile              // Редактируемые несекретные параметры.
	port           string                             // Текстовое представление SSH-порта.
	secret         string                             // Временный пароль либо passphrase одной попытки.
	secretEpoch    uint64                             // Новая идентичность редактора после очистки секрета.
	editorEpoch    uint64                             // Новая идентичность полей при выборе другого профиля.
	generation     uint64                             // Номер действующей попытки или подключения.
	connecting     bool                               // Выполняется подключение в отдельной goroutine.
	cancel         context.CancelFunc                 // Отмена текущей попытки и SSH-сессии.
	connection     *connection.Connection             // Единственный действующий туннель.
	webView        *mygo.WebView                      // Изолированная встроенная панель текущего сервера.
	challenge      *connection.HostKeyChallenge       // Неизвестный ключ для явного подтверждения.
	message        string                             // Понятный результат последнего действия.
	messageError   bool                               // Сообщение обозначает ошибку.
	dialogBusy     bool                               // Открыт native диалог выбора файла.
	pendingName    string                             // Имя ожидающего разового профиля без его содержимого.
	saveData       *connection.PendingProfileDownload // Профиль во время выбора пути сохранения.
	saveConnection *connection.Connection             // Соединение, удерживающее выдачу до завершения сохранения.
	closed         bool                               // Главное окно уже завершает работу.
	ctx            context.Context                    // Время жизни приложения.
	stop           context.CancelFunc                 // Остановка фонового наблюдателя.
}

// newDesktopApp читает только несекретные настройки и готовит новую форму.
func newDesktopApp(directory string) *DesktopApp {
	ctx, stop := context.WithCancel(context.Background())
	app := &DesktopApp{directory: directory, ctx: ctx, stop: stop}
	profiles, err := connection.LoadProfiles(directory)
	if err != nil {
		app.setMessage("Не удалось прочитать сохранённые подключения: "+err.Error(), true)
	} else {
		app.profiles = profiles
		app.profilesLoaded = true
	}
	if len(profiles) > 0 {
		app.selectProfile(profiles[0])
	} else {
		app.newProfile()
	}
	return app
}

// setMessage ограничивает длину диагностического текста без записи в журнал.
func (app *DesktopApp) setMessage(message string, failed bool) {
	runes := []rune(message)
	if len(runes) > 1000 {
		runes = runes[:1000]
	}
	app.message, app.messageError = string(runes), failed
}

// clearSecret сбрасывает пароль и создаёт новый редактор без прежней истории undo.
func (app *DesktopApp) clearSecret() {
	app.secret = ""
	app.secretEpoch++
}

// newProfile открывает пустое подключение с независимым случайным идентификатором.
func (app *DesktopApp) newProfile() {
	if app.connecting || app.connection != nil || app.dialogBusy {
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		app.setMessage("Не удалось подготовить новое подключение.", true)
		return
	}
	app.selectProfile(connection.SSHProfile{ID: hex.EncodeToString(id[:]), User: "root", Port: 22, AuthMode: "password"})
}

// selectProfile переносит несекретные поля в новую форму и забывает прежний пароль.
func (app *DesktopApp) selectProfile(profile connection.SSHProfile) {
	if app.connecting || app.connection != nil || app.dialogBusy {
		return
	}
	app.draft, app.port = profile, strconv.Itoa(profile.Port)
	app.challenge = nil
	app.editorEpoch++
	app.clearSecret()
}

// currentProfile проверяет порт и нормализует только крайние пробелы формы.
func (app *DesktopApp) currentProfile() (connection.SSHProfile, error) {
	profile := app.draft
	port, err := strconv.Atoi(strings.TrimSpace(app.port))
	if err != nil || port < 1 || port > 65535 {
		return profile, errors.New("Укажите SSH-порт от 1 до 65535.")
	}
	profile.Name, profile.Host, profile.User = strings.TrimSpace(profile.Name), strings.TrimSpace(profile.Host), strings.TrimSpace(profile.User)
	profile.KeyPath, profile.Port = strings.TrimSpace(profile.KeyPath), port
	if profile.Name == "" || profile.Host == "" || profile.User == "" {
		return profile, errors.New("Заполните имя подключения, адрес VPS и пользователя SSH.")
	}
	return profile, nil
}

// saveProfile сохраняет параметры по отдельной кнопке, никогда не включая секрет.
func (app *DesktopApp) saveProfile() {
	if app.connecting || app.connection != nil || app.dialogBusy {
		return
	}
	if !app.profilesLoaded {
		app.setMessage("Файл подключений не прочитан. Исправьте его доступность и перезапустите приложение перед сохранением.", true)
		return
	}
	profile, err := app.currentProfile()
	if err != nil {
		app.setMessage(err.Error(), true)
		return
	}
	profiles := append([]connection.SSHProfile(nil), app.profiles...)
	found := false
	for index := range profiles {
		if profiles[index].ID == profile.ID {
			profiles[index], found = profile, true
			break
		}
	}
	if !found {
		profiles = append(profiles, profile)
	}
	if err := connection.SaveProfiles(app.directory, profiles); err != nil {
		app.setMessage("Подключение не сохранено: "+err.Error(), true)
		return
	}
	app.profiles, app.draft = profiles, profile
	app.setMessage("Параметры подключения сохранены. Пароль не сохраняется.", false)
}

// connect начинает одну отменяемую попытку и очищает секрет в native редакторе.
func (app *DesktopApp) connect() {
	if app.connecting || app.connection != nil || app.dialogBusy || app.closed {
		return
	}
	profile, err := app.currentProfile()
	if err != nil {
		app.setMessage(err.Error(), true)
		return
	}
	credentials := connection.Credentials{}
	if profile.AuthMode == "key" {
		credentials.Passphrase = app.secret
	} else {
		credentials.Password = app.secret
	}
	app.clearSecret()
	app.challenge = nil
	app.generation++
	generation := app.generation
	ctx, cancel := context.WithCancel(app.ctx)
	app.cancel, app.connecting = cancel, true
	app.setMessage("Подключаемся по SSH и открываем панель…", false)
	go func() {
		connected, connectError := connection.Connect(ctx, app.directory, profile, credentials)
		credentials.Password, credentials.Passphrase = "", ""
		accepted := false
		mygo.RunOnMain(func() {
			if app.closed || app.generation != generation || ctx.Err() != nil {
				return
			}
			app.connecting = false
			if connectError != nil {
				cancel()
				app.cancel = nil
				var challenge *connection.HostKeyChallenge
				if errors.As(connectError, &challenge) {
					app.challenge = challenge
					app.setMessage("Этот SSH-ключ ещё не известен приложению. Сверьте отпечаток перед подтверждением.", false)
				} else {
					app.setMessage("Подключение не выполнено: "+connectError.Error(), true)
				}
			} else if viewError := app.openPanel(connected); viewError != nil {
				cancel()
				app.cancel = nil
				app.setMessage("Не удалось открыть встроенную панель: "+viewError.Error(), true)
			} else {
				app.connection, app.draft, accepted = connected, profile, true
				app.setMessage("SSH подключён. Войдите в панель её обычным секретом доступа.", false)
			}
			app.window.Invalidate()
		})
		if connected != nil && !accepted {
			_ = connected.Close()
		}
	}()
}

// trustHostKey сохраняет только явно показанный неизвестный ключ без повторного входа.
func (app *DesktopApp) trustHostKey() {
	if app.challenge == nil || app.connecting || app.closed || app.dialogBusy {
		return
	}
	if err := connection.TrustHostKey(app.directory, app.challenge); err != nil {
		app.setMessage("Ключ не сохранён: "+err.Error(), true)
		app.challenge = nil
		return
	}
	app.challenge = nil
	app.clearSecret()
	app.setMessage("SSH-ключ подтверждён. Введите пароль или passphrase ещё раз и подключитесь.", false)
}

// clearPendingSave уничтожает профиль, ожидающий выбора пути в native диалоге.
func (app *DesktopApp) clearPendingSave() {
	if app.saveData != nil {
		clear(app.saveData.Data)
		app.saveData = nil
	}
	if app.saveConnection != nil {
		app.saveConnection.FinishDownload()
		app.saveConnection = nil
	}
	app.pendingName = ""
}

// disconnect закрывает WebView, секреты, попытку подключения и принадлежащий ей туннель.
func (app *DesktopApp) disconnect() {
	app.generation++
	app.connecting = false
	app.challenge = nil
	app.clearSecret()
	if app.connection != nil {
		_ = app.connection.Close()
	}
	app.clearPendingSave()
	if app.cancel != nil {
		app.cancel()
		app.cancel = nil
	}
	if app.webView != nil {
		app.webView.Destroy()
		app.webView = nil
	}
	if app.connection != nil {
		_ = app.connection.Close()
		app.connection = nil
	}
	app.setMessage("SSH отключён. Выберите подключение или укажите новый VPS.", false)
}

// shutdown прекращает работу один раз и не сохраняет состояние удалённой страницы.
func (app *DesktopApp) shutdown() {
	if app.closed {
		return
	}
	app.closed = true
	app.stop()
	app.disconnect()
}

// startMonitor обновляет native кнопку сохранения и замечает закрытие SSH без busy polling.
func (app *DesktopApp) startMonitor() {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-app.ctx.Done():
				return
			case <-ticker.C:
				mygo.RunOnMain(func() {
					if app.closed {
						return
					}
					if app.saveData != nil && !time.Now().Before(app.saveData.ExpiresAt) {
						app.clearPendingSave()
						app.setMessage("Срок сохранения профиля истёк. Отзовите клиента и создайте нового.", true)
						app.window.Invalidate()
					}
					if app.connection == nil {
						return
					}
					select {
					case <-app.connection.Done():
						app.disconnect()
						app.setMessage("SSH-соединение завершено. Подключитесь заново.", true)
						app.window.Invalidate()
						return
					default:
					}
					name, available := app.connection.PendingDownload()
					if !available {
						name = ""
					}
					if name != app.pendingName {
						if name != "" {
							app.setMessage("«Передан браузеру» в панели означает, что профиль готов. Чтобы записать файл на диск, нажмите «Сохранить профиль .conf…» здесь, в приложении.", false)
						} else if app.pendingName != "" && app.saveData == nil {
							app.setMessage("Разовый профиль больше недоступен. Если файл не сохранён, отзовите клиента и создайте нового.", true)
						}
						app.pendingName = name
						app.window.Invalidate()
					}
				})
			}
		}
	}()
}
