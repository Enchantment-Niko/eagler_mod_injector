# eagler_mod_injector (CLI)

本项目是一个用于 Eaglercraft 资源注入的 **纯命令行 (CLI) 工具**。

**原作者**：
Kile_丶
[Bilibili 空间](https://space.bilibili.com/2028829888)

> **重要说明**：
> 1. 这是一个 **命令行版本**，没有图形界面，需要在终端或 CMD 中运行。
> 2. 该版本目前处于**初步阶段**，可以勉强完成基础的 EPW 资源修改，但**存在诸多已知 Bug**。
> 3. 本项目仅作技术交流，作者不提供后续 Bug 修复支持，请自行承担使用风险。

## 下载与国内网盘

为了方便国内用户下载，提供蓝奏云网盘链接：
[访问链接](https://wwbls.lanzouq.com/ijFqs4465tqf)

## 运行环境与准备

1. **安装 Python**：请前往 [Python 官网](https://python.org/downloads) 下载并安装最新版本的 Python。
2. **准备文件**：准备好你需要修改的 `EPW` 文件或包含 EPW 的 `HTML` 文件。

## 基础使用教程（防坑版）

**注意：因为 Bug 较多，建议先在副本上测试，不要直接操作原文件。**

在终端（CMD / PowerShell / Git Bash）中，切换到脚本所在目录，使用以下命令：

**1. 查看 HTML/EPW 内的文件列表（防瞎猜）**
```bash
# 列出 HTML 内嵌的 EPW 中的所有 EPK 档案
python script.py list --html "你的文件.html"

# 查看某个 EPK 里的具体文件（例如第 0 个），加 --search 可过滤关键词
python script.py list --html "你的文件.html" --epk 0 --search "lang"
```

**2. 提取文件（用于检查）**
```bash
# 提取 EPK 0 里面的指定文件
python script.py extract --html "你的文件.html" --epk 0 --name "assets/minecraft/lang/zh_cn.json"
```

**3. 注入资源（核心功能）**
```bash
# 把单个文件注入到 EPK 0
python script.py inject --html "你的文件.html" --epk 0 --source "你的新文件.json" --target "assets/minecraft/lang" --output "新文件.html"

# 把整个目录注入进去
python script.py inject --html "你的文件.html" --epk 0 --source "./你的资源目录" --output "新文件.html"
```

*(注：如果遇到报错、黑屏、或者注入后文件体积异常增大，纯属正常现象（因旧版工具有遗留 Bug），可以尝试让 AI 帮你排查代码或自行修复。)*

---
*Disclaimer: 本项目仅供学习与技术研究，请勿用于商业用途。*