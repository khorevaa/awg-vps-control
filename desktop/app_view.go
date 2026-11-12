package main

import (
	"fmt"

	"github.com/egoist/mygo/ui"
)

// render строит native выбор SSH либо панель текущего VPS внутри того же окна.
func (app *DesktopApp) render(c *ui.Context) {
	if app.connection != nil && app.webView != nil {
		app.renderPanel(c)
		return
	}
	ui.Column(c).Fill().Padding(26).Gap(18).Children(func() {
		ui.Text(c, "AWG VPS Control").FontSize(28).Bold()
		ui.Text(c, "Подключитесь к личному VPS по SSH. Панель откроется внутри приложения.").TextColor(c.Theme().TextMuted)
		ui.Row(c).FillWidth().Grow(1).MinHeight(0).AlignItems(ui.Stretch).Gap(28).Children(func() {
			ui.Column(c).Width(260).FillHeight().Gap(12).Children(func() {
				ui.Text(c, "Сохранённые подключения").Bold().FontSize(16)
				ui.Scroll(c).FillWidth().Grow(1).MinHeight(0).Children(func() {
					ui.Column(c).FillWidth().Gap(12).Children(func() {
						if len(app.profiles) == 0 {
							ui.Text(c, "Подключений пока нет. Заполните форму и сохраните параметры.").TextColor(c.Theme().TextMuted)
						}
						for _, profile := range app.profiles {
							ui.Column(c.Key(profile.ID)).FillWidth().Gap(4).Children(func() {
								if ui.Button(c, profile.Name).FillWidth().Selected(profile.ID == app.draft.ID).Disabled(app.connecting || app.dialogBusy).Clicked() {
									app.selectProfile(profile)
								}
								ui.Text(c, fmt.Sprintf("%s@%s:%d", profile.User, profile.Host, profile.Port)).FontSize(11).TextColor(c.Theme().TextMuted)
							})
						}
					})
				})
				if ui.Button(c.Key("new_profile"), "+ Новое подключение").FillWidth().Disabled(app.connecting || app.dialogBusy).Clicked() {
					app.newProfile()
				}
			})
			ui.Scroll(c).Grow(1).FillHeight().Children(func() {
				ui.Column(c.Key(app.editorEpoch)).FillWidth().MaxWidth(720).Gap(14).Children(func() {
					app.renderForm(c)
					app.renderChallenge(c)
					app.renderMessage(c)
				})
			})
		})
		ui.Text(c, "Пароли вводятся на каждое подключение. На компьютере сохраняются только параметры SSH и подтверждённые ключи серверов.").FontSize(11).TextColor(c.Theme().TextMuted)
	})
}

// renderForm связывает поля с несекретным профилем и отдельным временным редактором пароля.
func (app *DesktopApp) renderForm(c *ui.Context) {
	disabled := app.connecting || app.dialogBusy || app.challenge != nil
	ui.Text(c, "SSH-подключение").FontSize(20).Bold()
	ui.Text(c, "Имя подключения").FontSize(12)
	ui.TextInput(c.Key("connection_name"), &app.draft.Name).Label("Имя подключения").Placeholder("Например, личный VPS").MaxLength(80).FillWidth().Disabled(disabled)
	ui.Row(c).FillWidth().Gap(12).Children(func() {
		ui.Column(c).Grow(1).Gap(6).Children(func() {
			ui.Text(c, "Адрес VPS").FontSize(12)
			ui.TextInput(c.Key("host"), &app.draft.Host).Label("Адрес VPS").Placeholder("IP или DNS-имя").MaxLength(253).FillWidth().Disabled(disabled)
		})
		ui.Column(c).Width(100).Gap(6).Children(func() {
			ui.Text(c, "SSH-порт").FontSize(12)
			ui.TextInput(c.Key("port"), &app.port).Label("SSH-порт").MaxLength(5).FillWidth().Disabled(disabled)
		})
	})
	ui.Text(c, "Пользователь SSH").FontSize(12)
	ui.TextInput(c.Key("user"), &app.draft.User).Label("Пользователь SSH").MaxLength(64).FillWidth().Disabled(disabled)
	ui.Row(c).Gap(18).Children(func() {
		before := app.draft.AuthMode
		ui.Radio(c.Key("auth_password"), &app.draft.AuthMode, "password", "Пароль").Disabled(disabled)
		ui.Radio(c.Key("auth_key"), &app.draft.AuthMode, "key", "SSH-ключ").Disabled(disabled)
		if app.draft.AuthMode != before {
			app.clearSecret()
		}
	})
	if app.draft.AuthMode == "key" {
		ui.Text(c, "Файл приватного SSH-ключа").FontSize(12)
		ui.Row(c).FillWidth().Gap(8).Children(func() {
			ui.TextInput(c.Key("key_path"), &app.draft.KeyPath).Label("Файл приватного SSH-ключа").Placeholder("Полный путь к ключу OpenSSH").MaxLength(4096).Grow(1).Disabled(disabled)
			if ui.Button(c.Key("choose_key"), "Выбрать…").Disabled(disabled).Clicked() {
				app.chooseKey()
			}
		})
	}
	label := "Пароль SSH"
	if app.draft.AuthMode == "key" {
		label = "Passphrase ключа, если установлен"
	}
	ui.Text(c, label).FontSize(12)
	ui.Box(c.Key(fmt.Sprintf("secret_epoch_%d", app.secretEpoch))).FillWidth().Children(func() {
		ui.TextInput(c.Key("password"), &app.secret).Password().Label(label).MaxLength(4096).FillWidth().Disabled(disabled)
	})
	ui.Row(c).FillWidth().Gap(10).Children(func() {
		if app.connecting {
			if ui.Button(c.Key("cancel"), "Отменить подключение").Clicked() {
				app.disconnect()
			}
		} else {
			if ui.PrimaryButton(c.Key("connect"), "Подключиться").Disabled(disabled).Clicked() {
				app.connect()
			}
			if ui.Button(c.Key("save_profile"), "Сохранить параметры").Disabled(disabled).Clicked() {
				app.saveProfile()
			}
		}
	})
}

// renderChallenge показывает точный отпечаток неизвестного SSH-ключа до его сохранения.
func (app *DesktopApp) renderChallenge(c *ui.Context) {
	if app.challenge == nil {
		return
	}
	ui.Column(c).FillWidth().Padding(16).Gap(10).Border(1, c.Theme().Warning).Children(func() {
		ui.Text(c, "Подтвердите SSH-ключ сервера").Bold()
		ui.Text(c, app.challenge.Address).Selectable()
		ui.Text(c, app.challenge.Algorithm).FontSize(12).TextColor(c.Theme().TextMuted)
		ui.Text(c, app.challenge.Fingerprint).Selectable()
		ui.Text(c, "Сверьте этот SHA256-отпечаток через консоль провайдера или другим известным способом. Изменившийся доверенный ключ приложение не принимает.").FontSize(12)
		ui.Row(c).Gap(10).Children(func() {
			if ui.PrimaryButton(c.Key("trust"), "Отпечаток совпадает — доверять").Clicked() {
				app.trustHostKey()
			}
			if ui.Button(c.Key("reject_trust"), "Отмена").Clicked() {
				app.challenge = nil
				app.setMessage("Подтверждение SSH-ключа отменено.", false)
			}
		})
	})
}

// renderMessage показывает состояние без вывода пароля, приватных ключей или профиля.
func (app *DesktopApp) renderMessage(c *ui.Context) {
	if app.message == "" {
		return
	}
	color := c.Theme().TextMuted
	if app.messageError {
		color = c.Theme().Danger
	}
	ui.Text(c.Key("status"), app.message).TextColor(color).FontSize(12)
}

// renderPanel оставляет native управление соединением над встроенной удалённой страницей.
func (app *DesktopApp) renderPanel(c *ui.Context) {
	ui.Column(c).Fill().Children(func() {
		ui.Column(c).FillWidth().Padding(12, 18).Gap(8).Children(func() {
			ui.Row(c).FillWidth().Gap(14).Children(func() {
				ui.Text(c, app.draft.Name).Bold().FontSize(17)
				ui.Text(c, fmt.Sprintf("SSH · %s@%s:%d", app.draft.User, app.draft.Host, app.draft.Port)).FontSize(12).TextColor(c.Theme().TextMuted)
				ui.Spacer(c)
				if app.pendingName != "" {
					if ui.PrimaryButton(c.Key("save_download"), "Сохранить профиль .conf…").Disabled(app.dialogBusy).Clicked() {
						app.saveDownload()
					}
				}
				if ui.Button(c.Key("disconnect"), "Отключиться").Clicked() {
					app.disconnect()
				}
			})
			app.renderMessage(c)
		})
		if app.webView != nil {
			ui.WebView(c.Key("server_panel"), app.webView).Grow(1).FillWidth()
		}
	})
}
