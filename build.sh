#!/bin/bash

# 💡 確保任何一行指令失敗時，腳本會立刻停止，避免打包出壞掉的成品
set -e

echo "========================================="
echo " 🚀 開始執行 PQC 掃描器跨平台自動化打包..."
echo "========================================="

# 1. 清理舊的打包成品
echo "🧹 正在清理上一次的舊壓縮檔..."
rm -f PQC-Scanner-MacOS.tar.gz
rm -f PQC-Scanner-Windows.zip

# 2. 打包 Mac 版本
echo "🍎 正在編譯 Mac 綠色免安裝包 (.tar.gz)..."
mkdir -p PQC-Scanner-MacOS
cp -R src venv MacOS一鍵啟動.command PQC-Scanner-MacOS/
tar -czf PQC-Scanner-MacOS.tar.gz PQC-Scanner-MacOS/
rm -rf PQC-Scanner-MacOS
echo " └─ 🟢 Mac 版本打包成功！"

# 3. 打包 Windows 版本
echo "💻 正在編編譯 Windows 綠色免安裝包 (.zip)..."
mkdir -p PQC-Scanner-Windows
cp -R src env Windows一鍵啟動.bat PQC-Scanner-Windows/
# -q 代表安靜模式，不讓滿滿的壓縮日誌塞爆你的終端機視窗
zip -r -q PQC-Scanner-Windows.zip PQC-Scanner-Windows/
rm -rf PQC-Scanner-Windows
echo " └─ 🟢 Windows 版本打包成功！"

echo "========================================="
echo " 🎉 雙系統免安裝綠色包，全自動打包完成！"
echo "-----------------------------------------"
echo "請至目錄下將以下兩個產出物上傳至 GitHub Releases："
echo " 📦 1. PQC-Scanner-MacOS.tar.gz"
echo " 📦 2. PQC-Scanner-Windows.zip"
echo "========================================="
