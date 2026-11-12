package main

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/egoist/mygo"
)

// chooseKey показывает native выбор файла, не читая содержимое приватного ключа.
func (app *DesktopApp) chooseKey() {
	if app.dialogBusy || app.connecting || app.connection != nil || app.closed {
		return
	}
	app.dialogBusy = true
	generation, editor := app.generation, app.editorEpoch
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: app.window, Title: "Выберите приватный SSH-ключ", Multiple: false})
		mygo.RunOnMain(func() {
			app.dialogBusy = false
			if app.closed || app.generation != generation || app.editorEpoch != editor {
				return
			}
			if err != nil {
				app.setMessage("Не удалось выбрать файл SSH-ключа.", true)
			} else if len(paths) == 1 {
				app.draft.KeyPath = paths[0]
				app.clearSecret()
			}
			app.window.Invalidate()
		})
	}()
}

// saveDownload забирает профиль один раз и держит его в памяти только до решения native диалога.
func (app *DesktopApp) saveDownload() {
	if app.connection == nil || app.dialogBusy || app.closed {
		return
	}
	source := app.connection
	profile, err := source.TakeDownload()
	if err != nil {
		app.pendingName = ""
		app.setMessage("Разовый профиль недоступен. Если файл не сохранён, отзовите клиента и создайте нового.", true)
		return
	}
	app.saveData, app.pendingName, app.dialogBusy = profile, "", true
	app.saveConnection = source
	generation := app.generation
	filename := profile.Filename
	app.setMessage("Выберите, куда сохранить .conf. Отмена завершит разовую выдачу.", false)
	go func() {
		selected, dialogError := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent: app.window, Title: "Сохранить разовый профиль AWG", DefaultPath: filename,
			Filters: []mygo.FileFilter{{Name: "Профиль AWG", Extensions: []string{"conf"}}},
		})
		var content []byte
		mygo.RunOnMain(func() {
			app.dialogBusy = false
			if app.closed || app.generation != generation || app.saveData == nil {
				return
			}
			if dialogError != nil || selected == "" {
				app.clearPendingSave()
				app.setMessage("Профиль не сохранён и удалён из памяти. Для новой выдачи отзовите клиента и создайте нового.", true)
			} else if !time.Now().Before(app.saveData.ExpiresAt) {
				app.clearPendingSave()
				app.setMessage("Срок сохранения профиля истёк. Создайте нового клиента.", true)
			} else {
				content = app.saveData.Data
				app.saveData.Data = nil
				app.saveData, app.saveConnection = nil, nil
				app.setMessage("Сохраняем профиль…", false)
			}
			app.window.Invalidate()
		})
		if len(content) == 0 {
			return
		}
		defer func() {
			clear(content)
			source.FinishDownload()
		}()
		saveError := saveProfileFile(selected, content)
		mygo.RunOnMain(func() {
			if app.closed || app.generation != generation {
				return
			}
			if saveError != nil {
				app.setMessage("Не удалось сохранить профиль. Разовая выдача завершена; отзовите клиента и создайте нового.", true)
			} else {
				app.setMessage("Профиль .conf сохранён. Импортируйте его в Amnezia на нужном устройстве.", false)
			}
			app.window.Invalidate()
		})
	}()
}

// saveProfileFile атомарно записывает ограниченный профиль по явно выбранному абсолютному пути.
func saveProfileFile(destination string, content []byte) error {
	if !filepath.IsAbs(destination) || len(content) == 0 || len(content) > 65536 {
		return errors.New("недопустимый путь или размер профиля")
	}
	directory := filepath.Dir(destination)
	file, err := os.CreateTemp(directory, ".awg_profile_*")
	if err != nil {
		return errors.New("каталог сохранения недоступен")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return errors.New("не удалось ограничить доступ к профилю")
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return errors.New("не удалось записать профиль")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("не удалось сохранить профиль на диске")
	}
	if err := file.Close(); err != nil {
		return errors.New("не удалось завершить запись профиля")
	}
	if err := os.Rename(temporary, destination); err != nil {
		return errors.New("не удалось разместить профиль по выбранному пути")
	}
	return nil
}
