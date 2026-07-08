# tbox 项目环境配置

## Android 构建环境变量

构建 Android APK 前需设置以下环境变量：

```bash
export ANDROID_HOME=/opt/tools
export ANDROID_NDK_HOME=/usr/lib/android-sdk/ndk/28.2.13676358
export PATH=$PATH:$(go env GOPATH)/bin
```

- SDK: `/opt/tools` (build-tools 34.0.0, platforms android-34)
- NDK: `/usr/lib/android-sdk/ndk/28.2.13676358`
- gomobile: 需通过 `go install golang.org/x/mobile/cmd/gomobile@latest` 安装，然后 `gomobile init`

## 构建命令

```bash
# 编译 APK（先构建 AAR，再 assembleDebug）
make android-apk

# 仅构建 AAR
make android

# 编译 Go 二进制
make build
```

APK 输出路径：`android/app/build/outputs/apk/debug/app-debug.apk`

## ADB 设备

设备 FIONJFFU9XDM5LPB (USB 连接)，安装命令：

```bash
adb install android/app/build/outputs/apk/debug/app-debug.apk
```
