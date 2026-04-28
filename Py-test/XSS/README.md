# 基础 XSS 本地靶场与验证脚本

这份脚本包含几个最基础 XSS 场景整理成了**本地可运行的靶场**和**对应验证脚本**。它只用于学习、复现 PortSwigger Lab 思路，或验证你自己有授权的测试环境。

> 安全边界：脚本只使用 `alert(1)` 这类无害 payload，不包含 Cookie 窃取、数据外带、绕过字典、批量扫描公网目标等逻辑。请只在本地或明确授权的环境中使用。


## 覆盖的基础场景

脚本覆盖了几类入门 XSS 场景：

1. 反射型 XSS：输入直接出现在 HTML 正文中。
2. 存储型 XSS：提交的内容被保存后再展示到 HTML 正文中。
3. DOM XSS：前端 JavaScript 从 URL 参数读取内容，并写入 `document.write`。
4. DOM XSS：前端 JavaScript 从 URL 参数读取内容，并写入 `innerHTML`。
5. DOM XSS：前端 JavaScript 从 URL 参数读取内容，并写入链接的 `href`。
6. 属性上下文反射型 XSS：输入被拼接进 HTML 属性值中。
7. 属性上下文存储型 XSS：提交的链接被保存后作为 `<a href="...">` 输出。

## Python 版做了什么

Python 目录里包含两个脚本：

### `xss_basic_lab.py`

这是一个基于 Python 标准库 `http.server` 写的本地脆弱靶场。它启动后会提供多个路由，每个路由模拟一种基础 XSS 场景。

它主要做了这些事情：

- 读取 URL 查询参数或表单提交内容。
- 故意不做 HTML 转义或属性转义。
- 把用户输入直接拼接进 HTML 正文、HTML 属性、JavaScript DOM sink 或链接 `href` 中。
- 对存储型场景，使用内存里的列表保存提交内容，刷新页面后继续展示。

启动方式：

```bash
cd python
python3 xss_basic_lab.py --host 127.0.0.1 --port 8008
```

### `xss_verify_basic.py`

这是 Python 版验证脚本，用来访问上面的本地靶场并检查 payload 是否被原样反射或存储。

它主要做了这些事情：

- 通过 HTTP 请求访问各个测试路由。
- 构造对应场景的基础 payload，例如 `<script>alert(1)</script>`、`"><svg onload=alert(1)>`、`javascript:alert(1)` 等。
- 对反射型和存储型场景，检查响应 HTML 中是否出现未转义的 payload。
- 对 DOM 型、鼠标悬停、点击链接这类需要浏览器执行的场景，提供可选的 Playwright 模式来监听 `alert` 弹窗。

普通静态验证：

```bash
cd python
python3 xss_verify_basic.py --base http://127.0.0.1:8008
```

可选浏览器验证：

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
python3 xss_verify_basic.py --base http://127.0.0.1:8008 --browser
```
