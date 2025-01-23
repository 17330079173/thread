import requests
import re
from bs4 import BeautifulSoup

# 正则表达式模式，用于匹配敏感信息
sensitive_patterns = {
    '账户': r'[a-zA-Z0-9._%+-]+',  # 用户名
    '密码': r'[a-zA-Z0-9!@#$%^&*()_+-=]{8,}',  # 密码（至少8个字符）
    '手机号': r'(?:\+?\d{1,3}[ -]?)?(?:\(?\d{2,4}\)?[ -]?)?\d{7,10}',  # 手机号
    '电子邮件': r'[a-zA-Z0-9._%+-]+@[a-zA0-9.-]+\.[a-zA-Z]{2,}',  # 邮箱
    '密钥': r'-----BEGIN [A-Za-z ]+-----\n([A-Za-z0-9+/=]+\n)+-----END [A-Za-z ]+-----',  # 公私钥
    '公钥': r'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=]+\n)+-----END PUBLIC KEY-----',  # 公钥
    '私钥': r'-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+/=]+\n)+-----END PRIVATE KEY-----'  # 私钥
}

# 详细的正则表达式，用于匹配API路径
api_pattern = re.compile(r'(["\'])(/[^"\']{1,990})(?:\?[^"\']*)?\1')

# 爬取目标网站的HTML源代码
def get_html(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"请求失败，HTTP状态码: {response.status_code}")
            return None
    except Exception as e:
        print(f"请求错误: {e}")
        return None

# 保存HTML源码到文件
def save_html_to_file(html_code):
    try:
        with open("html.html", "w", encoding="utf-8") as f:
            f.write(html_code)
        print("HTML 页面已保存到 html.html")
    except Exception as e:
        print(f"保存HTML文件失败: {e}")

# 提取页面中的JS文件（包括外部JS和内联JS）
def extract_js_files_and_inline_js(html):
    external_js_files = re.findall(r'<script\s+src=["\']([^"\']+\.js)["\'][^>]*>', html)
    inline_js_code = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)  # re.DOTALL 使 . 可以匹配换行符
    return external_js_files, inline_js_code

# 检查JS文件中是否包含敏感信息
def check_sensitive_in_js(js_code):
    matches = {}
    for key, pattern in sensitive_patterns.items():
        matches[key] = re.findall(pattern, js_code)
    return matches

# 保存敏感信息和对应的JS文件地址到key.txt
def save_sensitive_info_to_file(js_file, sensitive_info):
    try:
        with open("key.txt", "a", encoding="utf-8") as f:
            f.write(f"JS 文件地址: {js_file}\n")
            for info_type, items in sensitive_info.items():
                if items:
                    f.write(f"  {info_type}: {items[:3]}\n")  # 打印前三个匹配项
            f.write("\n")
        print("敏感信息已保存到 key.txt")
    except Exception as e:
        print(f"保存敏感信息失败: {e}")

# 下载并分析外部JS文件
def analyze_external_js(js_file):
    try:
        js_content = requests.get(js_file).text
        sensitive_info = check_sensitive_in_js(js_content)
        if sensitive_info:
            save_sensitive_info_to_file(js_file, sensitive_info)
    except Exception as e:
        print(f"无法下载 JS 文件 {js_file}: {e}")

# 分析页面中的JS代码（内联JS和外部JS）
def analyze_js(html):
    external_js_files, inline_js_code = extract_js_files_and_inline_js(html)

    # 分析外部JS文件
    for js_file in external_js_files:
        analyze_external_js(js_file)

    # 分析内联JS代码
    for js_code in inline_js_code:
        sensitive_info = check_sensitive_in_js(js_code)
        if sensitive_info:
            save_sensitive_info_to_file("内联JS", sensitive_info)

# 提取并保存API接口信息到文件
def extract_and_save_api_urls(html):
    try:
        api_urls = re.findall(api_pattern, html)
        with open("api.txt", "w", encoding="utf-8") as f:
            for api_url in api_urls:
                api_path = api_url[1]
                f.write(api_path + "\n")
                
                # 如果API路径包含查询参数(?), 将查询参数单独输出
                if '?' in api_path:
                    base_path, query_params = api_path.split('?', 1)
                    f.write(f"{base_path}?{query_params}\n")
        print("API接口信息已保存到 api.txt")
    except Exception as e:
        print(f"保存API信息失败: {e}")

# 主程序
def main():
    url = input("请输入目标网站URL: ")

    # 获取网页 HTML
    new_html = get_html(url)
    if new_html:
        # 将HTML源码保存为html.html
        save_html_to_file(new_html)

        # 提取并保存API接口路径到 api.txt
        extract_and_save_api_urls(new_html)

        # 分析 JS 文件中的敏感信息
        analyze_js(new_html)
    else:
        print("无法抓取该网站")

if __name__ == "__main__":
    main()
