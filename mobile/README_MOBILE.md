# NSocial Mobile (Android + iOS)

Этот проект — нативная оболочка (Capacitor), которая открывает https://nsocial.onrender.com/ как отдельное приложение.

## Требования
- Node.js + npm
- Android: Android Studio + JDK 17
- iOS: Xcode (только macOS)

## Установка и генерация платформ
```powershell
cd mobile
npm install
npx cap add android
npx cap add ios
npx cap sync
```

## Запуск
```powershell
npx cap open android
npx cap open ios
```

## Иконки и Splash Screen
Исходники лежат в `mobile\resources\icon.svg` и `mobile\resources\splash.svg`.

Сгенерировать ассеты для iOS/Android:
```powershell
cd mobile
npx @capacitor/assets generate --icon resources\icon.svg --splash resources\splash.svg
npx cap sync
```

Если генератор не принимает SVG, экспортируй PNG 1024x1024 и укажи его вместо SVG.

## Push‑уведомления (Apple Push)
Требуется Apple Developer аккаунт, ключ APNs и bundle id.

1. В Apple Developer:
- App ID с включенным `Push Notifications`.
- Ключ APNs (.p8) и его `Key ID`.
2. В Xcode:
- Включить `Push Notifications` capability.
- Включить `Background Modes` → `Remote notifications`.
3. Переменные окружения для сервера:
- `NSOCIAL_APNS_KEY_ID` — Key ID
- `NSOCIAL_APNS_TEAM_ID` — Team ID
- `NSOCIAL_APNS_BUNDLE_ID` — Bundle ID (например `com.nsocial.app`)
- `NSOCIAL_APNS_KEY_PATH` или `NSOCIAL_APNS_KEY_BASE64`
- `NSOCIAL_APNS_USE_SANDBOX` — `true` для dev, `false` для production

После этого push‑токен регистрируется из приложения и сервер шлет push при новых сообщениях.

## Сборка
- Android: в Android Studio "Build > Generate Signed Bundle / APK"
- iOS: в Xcode "Product > Archive"

## Если поменяется адрес сервера
Измени `server.url` в `mobile\capacitor.config.ts` и запусти:
```powershell
npx cap sync
```
