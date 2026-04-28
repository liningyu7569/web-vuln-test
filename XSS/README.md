# 基础 XSS 本地靶场与验证脚本

这份脚本包含几个最基础 XSS 场景整理成了**本地可运行的靶场**和**对应验证脚本**。它只用于学习、复现 PortSwigger Lab 思路，或验证你自己有授权的测试环境。

> 安全边界：脚本只使用 `alert(1)` 这类无害 payload，不包含 Cookie 窃取、数据外带、绕过字典、批量扫描公网目标等逻辑。请只在本地或明确授权的环境中使用。

## 目录结构


## 覆盖的基础场景

脚本覆盖了几类入门 XSS 场景：

1. 反射型 XSS：输入直接出现在 HTML 正文中。
2. 存储型 XSS：提交的内容被保存后再展示到 HTML 正文中。
3. DOM XSS：前端 JavaScript 从 URL 参数读取内容，并写入 `document.write`。
4. DOM XSS：前端 JavaScript 从 URL 参数读取内容，并写入 `innerHTML`。
5. DOM XSS：前端 JavaScript 从 URL 参数读取内容，并写入链接的 `href`。
6. 属性上下文反射型 XSS：输入被拼接进 HTML 属性值中。
7. 属性上下文存储型 XSS：提交的链接被保存后作为 `<a href="...">` 输出。

## Go 版做了什么

Go 目录里同样包含两个脚本：

### `xss_basic_lab.go`

这是一个基于 Go 标准库 `net/http` 写的本地脆弱靶场。功能和 Python 版基本一致，用来模拟博客里的基础 XSS 场景。

它主要做了这些事情：

- 用 `http.HandleFunc` 注册多个测试路由。
- 从 URL 参数或 POST 表单中读取用户输入。
- 故意不使用 `html/template` 的自动转义，而是用字符串拼接输出 HTML。
- 用内存变量保存存储型 XSS 的提交内容。
- 在 DOM 场景页面中写入简单的前端 JavaScript，让浏览器从 URL 参数读取值后写入 DOM。

启动方式：

```bash
cd go
go run xss_basic_lab.go -addr 127.0.0.1:8009
```

### `xss_verify_basic.go`

这是 Go 版验证脚本，保持了“只依赖标准库”的实现方式。

它主要做了这些事情：

- 使用 `net/http` 访问本地靶场。
- 使用 `url.Values` 构造查询参数和表单提交。
- 对能通过 HTTP 响应判断的场景，检查响应体中是否包含未转义 payload。
- 对必须依赖浏览器事件或 DOM 执行的场景，输出手工验证 URL，方便你复制到浏览器中观察 `alert(1)` 是否触发。

运行方式：

```bash
cd go
go run xss_verify_basic.go -base http://127.0.0.1:8009
```

## 简单实现原理

这些脚本的核心思路很简单：

1. **本地靶场负责制造漏洞上下文**  
   例如把用户输入直接放进 HTML 正文：

   ```html
   <p>搜索结果：用户输入</p>
   ```

   或者直接放进属性：

   ```html
   <input value="用户输入">
   ```

   如果没有做转义，攻击字符串就可能跳出当前上下文并变成可执行脚本。

2. **验证脚本负责投递 payload 并检查结果**  
   对反射型和存储型 XSS，只要响应 HTML 中出现了未转义的 payload，就说明输入被危险地输出到了页面中。

3. **DOM 型场景需要浏览器参与**  
   DOM XSS 的漏洞点通常不在服务端响应里，而在前端 JavaScript 执行时。例如页面脚本从 `location.search` 读取参数，然后写入 `innerHTML`。这种情况最好用真实浏览器验证，所以 Python 版提供了 Playwright 可选模式，Go 版则输出手工验证链接。

