#!/bin/bash
# ============================================================
# 智能 Python 学习环境配置脚本（自动检测 Python 版本）
# 用法：
#   ./setup-python.sh [项目目录]
#   - 带参数：使用指定目录（Unix风格路径，如 /d/myproject）
#   - 无参数：在当前目录下创建 年月日-时分 目录作为项目根目录
# ============================================================

set -e  # 遇到错误立即退出

# ---------- 处理命令行参数：决定 PROJECT_ROOT ----------
if [ -n "$1" ]; then
    # 使用传入的第一个参数作为项目目录
    if cd "$1" 2>/dev/null; then
        PROJECT_ROOT=$(pwd)
        echo "📁 使用指定项目目录: $PROJECT_ROOT"
    else
        echo "❌ 无法进入目录: $1"
        exit 1
    fi
else
    # 无参数：在当前目录创建时间戳目录
    TIMESTAMP=$(date +%Y%m%d-%H%M)
    PROJECT_DIR_NAME="$TIMESTAMP"
    mkdir -p "$PROJECT_DIR_NAME"
    cd "$PROJECT_DIR_NAME"
    PROJECT_ROOT=$(pwd)
    echo "📁 创建新项目目录: $PROJECT_ROOT"
fi

# ---------- 可选：手动指定 Python 路径（取消注释并填写）----------
# PYTHON_PATH="/c/Python314/python.exe"
# -------------------------------------------------------------

echo "🚀 开始配置 Python 学习环境..."

# ----- 1. 自动检测 Python 位置和版本 -----
if [ -z "$PYTHON_PATH" ]; then
    if command -v python &> /dev/null; then
        PYTHON_PATH=$(which python)
    else
        echo "❌ 未找到 Python，请先安装或手动指定 PYTHON_PATH"
        exit 1
    fi
fi
echo "🔍 检测到 Python: $PYTHON_PATH"

# 获取版本号（如 3.14.0 -> 314）
PY_VERSION=$("$PYTHON_PATH" --version 2>&1 | awk '{print $2}' | awk -F. '{print $1$2}')
if [ -z "$PY_VERSION" ]; then
    echo "❌ 无法获取 Python 版本号"
    exit 1
fi
echo "📌 Python 版本: $PY_VERSION"

# ----- 2. 设置虚拟环境名称和路径 -----
VENV_NAME="venv$PY_VERSION"
VENV_PATH="$PROJECT_ROOT/$VENV_NAME"
echo "📁 虚拟环境: $VENV_PATH"

# ----- 3. 确保在项目根目录 -----
cd "$PROJECT_ROOT"

# ----- 4. 创建虚拟环境 -----
"$PYTHON_PATH" -m venv "$VENV_NAME"
echo "✅ 虚拟环境 $VENV_NAME 创建成功"

# ----- 5. 激活虚拟环境（Windows Git Bash 语法）-----
# 使用 Scripts/activate 适用于 Git Bash / MSYS2 / Cygwin
if [ -f "$VENV_PATH/Scripts/activate" ]; then
    source "$VENV_PATH/Scripts/activate"
elif [ -f "$VENV_PATH/bin/activate" ]; then
    source "$VENV_PATH/bin/activate"  # Linux/macOS 路径
else
    echo "⚠️ 无法找到激活脚本，请手动激活虚拟环境"
fi
echo "🐍 虚拟环境已激活: $(which python)"

# ----- 6. 生成激活快捷脚本 activate.sh（使用相对路径）-----
cat > "$PROJECT_ROOT/activate.sh" << EOF
#!/bin/bash
# 激活当前项目的虚拟环境
# 用法：在项目根目录下执行 source activate.sh
# 注意：若将整个项目文件夹移动到其他位置，venv内部的激活脚本可能失效，
#       建议删除 venv$PY_VERSION 并重新运行本配置脚本。
source "./${VENV_NAME}/Scripts/activate"
EOF
chmod +x "$PROJECT_ROOT/activate.sh"
echo "✅ 已生成激活脚本 activate.sh（执行 source activate.sh 即可激活虚拟环境）"

# ----- 7. 安装 VSCode Python 扩展（如果有 code 命令）-----
if command -v code &> /dev/null; then
    code --install-extension ms-python.python --force
    echo "✅ VSCode Python 扩展安装/更新完成"
else
    echo "⚠️ 未找到 VSCode 命令，请手动安装 Python 扩展"
fi

# ----- 8. 创建项目标准目录 -----
mkdir -p src test output
touch src/demo.py
echo "✅ 已创建目录结构及空文件 src/demo.py"

# ----- 9. 生成 .gitignore -----
cat > .gitignore << 'EOF'
*.html
output/*
venv*/
__pycache__/
*.pyc
EOF
echo "✅ 已生成 .gitignore"

# ----- 10. 配置 VSCode 工作区设置（使用相对路径）-----
mkdir -p .vscode
cat > .vscode/settings.json << EOF
{
    "python.defaultInterpreterPath": "\${workspaceFolder}/${VENV_NAME}/Scripts/python.exe",
    "python.terminal.activateEnvironment": true,
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true
}
EOF
echo "✅ VSCode 工作区配置完成"

# ----- 11. 自动启动 VSCode -----
if command -v code &> /dev/null; then
    code .
    echo "🖥️ 已启动 VSCode，马上开始编程吧！"
else
    echo "⚠️ 请手动用 VSCode 打开目录：$PROJECT_ROOT"
fi

# ----- 12. 完成提示 -----
echo ""
echo "🎉 恭喜！所有配置已完成！"
echo "👉 项目位置：$PROJECT_ROOT"
echo "👉 虚拟环境：$VENV_NAME（已激活）"
echo "👉 激活脚本：$PROJECT_ROOT/activate.sh（新开终端后执行 source activate.sh）"
echo "👉 空代码文件：$PROJECT_ROOT/src/demo.py"
echo ""