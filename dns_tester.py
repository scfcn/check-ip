import os
import platform
import subprocess
import requests
import time
import json
import sys
import concurrent.futures
import csv
from datetime import datetime
import shutil
import random
from collections import defaultdict
import re
from string import Template

# ================ 配置参数 ================
PING_RETRY = 3  # 初始ping重试次数
API1_RETRY = 2  # API1测试次数
API2_RETRY = 2  # API2测试次数
API_TIMEOUT = 8  # 增加API请求超时时间
THREADS = 50     # 并发线程数
MAX_IPS_PER_DOMAIN = 0  # 0表示无限制，检测所有IP
CACHE_TTL_MINUTES = 30    # 缓存有效期（分钟）
PROGRESS_BAR_WIDTH = 50   # 进度条宽度

# 使用更稳定的DNS解析API
DNS_APIS = [
    {
        "name": "Google",
        "url": "https://dns.google/resolve",
        "params": {"name": "", "type": "A"},
        "headers": {"Accept": "application/dns-json"},
        "parser": lambda data: [answer["data"] for answer in data.get("Answer", []) if answer["type"] == 1]
    },
    {
        "name": "AliDNS",
        "url": "https://dns.alidns.com/resolve",
        "params": {"name": "", "type": "A"},
        "headers": {"Accept": "application/dns-json"},
        "parser": lambda data: [answer["data"] for answer in data.get("Answer", []) if answer["type"] == 1]
    }
]

# 使用更稳定的API端点
API1_URL = "https://api.oioweb.cn/api/http/ping?url="
API2_URL = "https://api.vvhan.com/api/ping?url="

# 文件配置
DOMAINS_FILE = "domains.txt"  # 输入域名文件
OUTPUT_DIR = "results"        # 输出目录
CACHE_FILE = os.path.join(OUTPUT_DIR, "ip_cache.json")  # IP缓存文件
IP_BLACKLIST_FILE = "ip_blacklist.txt"  # IP黑名单文件

# 全局状态
ip_cache = {}  # 格式: {ip: {"status": "success/timeout", "timestamp": float}}
domain_stats = defaultdict(dict)  # 域名统计信息
start_time = time.time()  # 全局开始时间

# ================ 输出工具 ================
class TermColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(message):
    """打印头部信息"""
    terminal_width = shutil.get_terminal_size().columns
    print("\n" + "=" * terminal_width)
    print(f"{TermColors.BOLD}{TermColors.HEADER}{message.center(terminal_width)}{TermColors.ENDC}")
    print("=" * terminal_width)

def print_subheader(message):
    """打印子头部信息"""
    print(f"\n{TermColors.BOLD}{TermColors.OKCYAN}{message}{TermColors.ENDC}")

def print_success(message):
    """打印成功信息"""
    print(f"{TermColors.OKGREEN}✓ {message}{TermColors.ENDC}")

def print_warning(message):
    """打印警告信息"""
    print(f"{TermColors.WARNING}⚠ {message}{TermColors.ENDC}")

def print_error(message):
    """打印错误信息"""
    print(f"{TermColors.FAIL}✗ {message}{TermColors.ENDC}")

def print_info(message):
    """打印一般信息"""
    print(f"{TermColors.OKBLUE}• {message}{TermColors.ENDC}")

def print_progress(domain, current, total, prefix=""):
    """打印进度条"""
    if total == 0:
        return
    
    filled_length = int(PROGRESS_BAR_WIDTH * current // total)
    bar = '■' * filled_length + '□' * (PROGRESS_BAR_WIDTH - filled_length)
    percent = 100.0 * current / total
    elapsed = time.time() - start_time
    eta = (elapsed / current) * (total - current) if current > 0 else 0
    
    sys.stdout.write(
        f"\r{prefix}{TermColors.BOLD}{domain[:30].ljust(30)}{TermColors.ENDC} "
        f"[{bar}] {percent:.1f}% "
        f"({current}/{total}) "
        f"Elapsed: {format_time(elapsed)} "
        f"ETA: {format_time(eta)}"
    )
    sys.stdout.flush()

def format_time(seconds):
    """格式化时间显示"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds // 60:.0f}m {seconds % 60:.0f}s"
    else:
        return f"{seconds // 3600:.0f}h {(seconds % 3600) // 60:.0f}m"

# ================ 核心功能 ================
def clean_previous_results():
    """清理之前的结果文件"""
    if os.path.exists(OUTPUT_DIR):
        try:
            # 删除之前的结果文件但保留缓存
            for filename in os.listdir(OUTPUT_DIR):
                file_path = os.path.join(OUTPUT_DIR, filename)
                if filename != "ip_cache.json" and os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            print_success("已清理之前的结果文件")
        except Exception as e:
            print_error(f"清理结果文件失败: {str(e)}")
    else:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    print_info(f"输出目录: {os.path.abspath(OUTPUT_DIR)}")

def load_cache():
    """加载IP缓存"""
    global ip_cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                ip_cache = json.load(f)
            print_success(f"已加载缓存: {len(ip_cache)} 条IP记录")
            
            # 清理过期缓存
            current_time = time.time()
            expired_keys = []
            for ip, data in ip_cache.items():
                age_minutes = (current_time - data["timestamp"]) / 60
                if age_minutes > CACHE_TTL_MINUTES:
                    expired_keys.append(ip)
            
            for ip in expired_keys:
                del ip_cache[ip]
            
            if expired_keys:
                print_warning(f"清理过期缓存: {len(expired_keys)} 条记录")
        except Exception as e:
            print_error(f"缓存加载失败: {str(e)}")
            ip_cache = {}

def save_cache():
    """保存IP缓存"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(ip_cache, f, indent=2)
        print_success(f"缓存已保存: {CACHE_FILE}")
    except Exception as e:
        print_error(f"缓存保存失败: {str(e)}")

def load_ip_blacklist():
    """加载IP黑名单"""
    blacklist = set()
    if os.path.exists(IP_BLACKLIST_FILE):
        try:
            with open(IP_BLACKLIST_FILE, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                        blacklist.add(ip)
            print_success(f"已加载IP黑名单: {len(blacklist)} 条记录")
        except Exception as e:
            print_error(f"黑名单加载失败: {str(e)}")
    return blacklist

def resolve_domain(domain):
    """使用稳定的大厂DNS API解析域名的A记录"""
    ips = []
    api_errors = []
    
    # 随机打乱API顺序，避免总是从同一个开始
    shuffled_apis = random.sample(DNS_APIS, len(DNS_APIS))
    
    for api in shuffled_apis:
        try:
            params = {k: (v if k != "name" else domain) for k, v in api["params"].items()}
            response = requests.get(
                api["url"], 
                params=params, 
                headers=api["headers"], 
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                resolved_ips = api["parser"](data)
                
                if resolved_ips:
                    ips.extend(resolved_ips)
                    print_info(f"{api['name']}解析成功: {domain} → {len(resolved_ips)}个IP地址")
                    # 成功获取到IP，不再尝试其他API
                    break
            else:
                error_msg = f"{api['name']} API错误: {domain} - HTTP {response.status_code}"
                api_errors.append(error_msg)
                print_warning(error_msg)
        except requests.exceptions.Timeout:
            error_msg = f"{api['name']} API请求超时: {domain}"
            api_errors.append(error_msg)
            print_warning(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = f"{api['name']} API请求错误: {domain} - {str(e)}"
            api_errors.append(error_msg)
            print_warning(error_msg)
        except Exception as e:
            error_msg = f"{api['name']}解析错误: {domain} - {str(e)}"
            api_errors.append(error_msg)
            print_warning(error_msg)
    
    # 去重
    ips = list(set(ips))
    if not ips:
        print_error(f"所有DNS API解析失败: {domain}")
        print_error("\n".join(api_errors))
    return ips

def ping_ip(ip):
    """Ping指定IP地址（高效版）"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    
    try:
        # 使用Popen避免等待子进程完成
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 设置超时
        try:
            stdout, stderr = process.communicate(timeout=2)
            return process.returncode == 0
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return False
    except Exception as e:
        return False

def test_ip_with_retry(ip, retries):
    """带重试的IP测试（高效版）"""
    for attempt in range(retries):
        if ping_ip(ip):
            return True
        elif attempt < retries - 1:  # 不是最后一次尝试
            time.sleep(0.1)  # 更短的延迟
    return False

def test_with_api(api_url, ip, retries, api_name):
    """通用的API测试函数"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'application/json'
    }
    
    for attempt in range(retries):
        try:
            start_time = time.time()
            # 添加随机参数避免缓存
            url = api_url + ip + f"&t={int(time.time())}"
            response = requests.get(url, headers=headers, timeout=API_TIMEOUT)
            response_time = int((time.time() - start_time) * 1000)  # 毫秒
            
            if response.status_code == 200:
                data = response.json()
                
                # 检查API1的成功条件
                if api_name == "API1" and data.get('code') == 200:
                    return {
                        "status": "success",
                        "api": api_name,
                        "attempt": attempt+1,
                        "response_time": response_time,
                        "api_time": data.get('data', {}).get('time', '未知')
                    }
                
                # 检查API2的成功条件
                elif api_name == "API2" and data.get('success') == True:
                    return {
                        "status": "success",
                        "api": api_name,
                        "attempt": attempt+1,
                        "response_time": response_time,
                        "api_time": data.get('time', '未知')
                    }
                else:
                    return {
                        "status": "failed",
                        "api": api_name,
                        "attempt": attempt+1,
                        "reason": f"状态码 {data.get('code')}" if api_name == "API1" else f"success={data.get('success')}",
                        "response_time": response_time
                    }
            else:
                return {
                    "status": "failed",
                    "api": api_name,
                    "attempt": attempt+1,
                    "reason": f"HTTP {response.status_code}",
                    "response_time": response_time
                }
                
        except requests.exceptions.Timeout:
            return {
                "status": "failed",
                "api": api_name,
                "attempt": attempt+1,
                "reason": f"超时({API_TIMEOUT}s)"
            }
        except requests.exceptions.RequestException as e:
            return {
                "status": "failed",
                "api": api_name,
                "attempt": attempt+1,
                "reason": str(e)
            }
        except json.JSONDecodeError:
            return {
                "status": "failed",
                "api": api_name,
                "attempt": attempt+1,
                "reason": "无效JSON响应"
            }
        
        # 不是最后一次尝试，则延迟
        if attempt < retries - 1:
            time.sleep(0.5 + random.random())  # 随机延迟避免请求风暴
    
    return {
        "status": "failed",
        "api": api_name,
        "attempt": "所有尝试",
        "reason": "未知错误"
    }

def test_single_ip(ip, ip_blacklist):
    """测试单个IP地址的连通性（高效版）"""
    # 检查黑名单
    if ip in ip_blacklist:
        return "blacklisted", {"ip": ip, "status": "blacklisted"}
    
    # 检查缓存
    current_time = time.time()
    if ip in ip_cache:
        cached_result = ip_cache[ip]
        age_minutes = (current_time - cached_result["timestamp"]) / 60
        if age_minutes < CACHE_TTL_MINUTES:
            status = cached_result["status"]
            return status, cached_result.get("details", {"ip": ip})
    
    # 开始测试
    test_details = {
        "ip": ip,
        "stages": []
    }
    
    # 第一阶段: 初始ping测试
    stage1 = {"name": "初始PING", "attempts": 1}
    if test_ip_with_retry(ip, 1):
        stage1["result"] = "success"
        test_details["stages"].append(stage1)
        status = "success"
    else:
        stage1["result"] = "timeout"
        test_details["stages"].append(stage1)
        
        # 第二阶段: 重试ping测试
        stage2 = {"name": f"PING重试({PING_RETRY}次)", "attempts": PING_RETRY}
        if test_ip_with_retry(ip, PING_RETRY):
            stage2["result"] = "success"
            test_details["stages"].append(stage2)
            status = "success"
        else:
            stage2["result"] = "timeout"
            test_details["stages"].append(stage2)
            
            # 第三阶段: API验证
            stage3 = {"name": "API验证", "attempts": API1_RETRY + API2_RETRY}
            
            # API1验证
            api1_result = test_with_api(API1_URL, ip, API1_RETRY, "API1")
            stage3["api1"] = api1_result
            
            if api1_result["status"] == "success":
                status = "success"
            else:
                # API2验证
                api2_result = test_with_api(API2_URL, ip, API2_RETRY, "API2")
                stage3["api2"] = api2_result
                status = "success" if api2_result["status"] == "success" else "timeout"
            
            test_details["stages"].append(stage3)
    
    # 保存结果到缓存
    test_details["timestamp"] = current_time
    ip_cache[ip] = {
        "status": status,
        "timestamp": current_time,
        "details": test_details
    }
    
    return status, test_details

def test_domain_ips(domain, ips, ip_blacklist, domain_index, total_domains):
    """测试单个域名的所有IP地址"""
    results = {
        "domain": domain,
        "total_ips": len(ips),
        "success_ips": [],
        "timeout_ips": [],
        "blacklisted_ips": [],
        "test_details": []
    }
    
    # 更新全局状态
    domain_stats[domain] = {
        "total": len(ips),
        "completed": 0,
        "start_time": time.time()
    }
    
    # 使用线程池测试所有IP
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(THREADS, len(ips))) as executor:
        future_to_ip = {executor.submit(test_single_ip, ip, ip_blacklist): ip for ip in ips}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                status, details = future.result()
                results["test_details"].append(details)
                
                if status == "success":
                    results["success_ips"].append(ip)
                elif status == "timeout":
                    results["timeout_ips"].append(ip)
                elif status == "blacklisted":
                    results["blacklisted_ips"].append(ip)
                
                # 更新进度
                domain_stats[domain]["completed"] += 1
                completed = domain_stats[domain]["completed"]
                total = domain_stats[domain]["total"]
                
                # 打印进度条
                prefix = f"[{domain_index}/{total_domains}] "
                print_progress(domain, completed, total, prefix)
                
            except Exception as e:
                print_error(f"测试IP {ip} 时出错: {str(e)}")
                results["timeout_ips"].append(ip)
                domain_stats[domain]["completed"] += 1
    
    # 完成进度条
    sys.stdout.write("\n")
    sys.stdout.flush()
    
    return results

def test_domain(domain, ip_blacklist, domain_index, total_domains):
    """测试单个域名"""
    print_subheader(f"开始测试域名 [{domain_index}/{total_domains}]: {domain}")
    
    # 解析域名
    ips = resolve_domain(domain)
    if not ips:
        print_warning(f"域名 {domain} 解析失败，跳过测试")
        return {
            "domain": domain,
            "total_ips": 0,
            "success_ips": [],
            "timeout_ips": [],
            "blacklisted_ips": [],
            "test_details": [],
            "error": "DNS解析失败"
        }
    
    # 测试所有IP
    test_start = time.time()
    results = test_domain_ips(domain, ips, ip_blacklist, domain_index, total_domains)
    elapsed = time.time() - test_start
    
    # 保存域名详细报告
    results["test_time"] = elapsed
    results["timestamp"] = datetime.now().isoformat()
    
    safe_domain = domain.replace('.', '_').replace('*', 'wildcard')
    report_file = os.path.join(OUTPUT_DIR, f"{safe_domain}.json")
    
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # 打印域名摘要
    success_count = len(results["success_ips"])
    timeout_count = len(results["timeout_ips"])
    blacklist_count = len(results.get("blacklisted_ips", []))
    total_count = results["total_ips"]
    
    success_rate = success_count / total_count * 100 if total_count > 0 else 0
    status_color = TermColors.OKGREEN if success_rate > 90 else TermColors.WARNING if success_rate > 70 else TermColors.FAIL
    
    print(f"{TermColors.BOLD}域名测试完成: {domain}{TermColors.ENDC}")
    print(f"  {TermColors.OKGREEN}✓ 成功IP: {success_count}/{total_count} ({success_rate:.1f}%){TermColors.ENDC}")
    print(f"  {TermColors.FAIL}✗ 超时IP: {timeout_count}/{total_count}{TermColors.ENDC}")
    if blacklist_count > 0:
        print(f"  {TermColors.WARNING}⚫ 黑名单IP: {blacklist_count}/{total_count}{TermColors.ENDC}")
    print(f"  测试耗时: {format_time(elapsed)}")
    
    return results

def generate_html_report(results, output_dir, ping_retry, api1_retry, api2_retry, cache_ttl):
    """使用模板生成HTML报告"""
    # 加载HTML模板
    with open('report_template.html', 'r', encoding='utf-8') as f:
        template = f.read()
    
    # 准备替换数据
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_year = datetime.now().strftime("%Y")
    html_file = os.path.join(output_dir, "index.html")
    
    # 统计数据
    total_domains = len(results)
    total_ips = 0
    total_success = 0
    total_timeout = 0
    total_blacklisted = 0
    total_test_time = 0
    
    # 收集域名数据
    domain_data = []
    for res in results:
        total_ips += res["total_ips"]
        total_success += len(res["success_ips"])
        total_timeout += len(res["timeout_ips"])
        total_blacklisted += len(res.get("blacklisted_ips", []))
        total_test_time += res.get("test_time", 0)
        
        success_rate = len(res["success_ips"]) / res["total_ips"] * 100 if res["total_ips"] > 0 else 0
        domain_data.append({
            "domain": res["domain"],
            "total_ips": res["total_ips"],
            "success": len(res["success_ips"]),
            "timeout": len(res["timeout_ips"]),
            "blacklisted": len(res.get("blacklisted_ips", [])),
            "success_rate": success_rate,
            "test_time": res.get("test_time", 0)
        })
    
    # 计算整体成功率
    success_rate = f"{total_success / total_ips * 100:.1f}" if total_ips > 0 else "0.0"
    
    # 生成域名行HTML
    domain_rows = []
    for data in domain_data:
        status_class = "success-badge" if data["success_rate"] > 90 else "warning-badge" if data["success_rate"] > 70 else "danger-badge"
        status_text = "优秀" if data["success_rate"] > 90 else "良好" if data["success_rate"] > 70 else "需关注"
        
        row = f"""
        <tr>
            <td><i class="fas fa-link"></i> {data['domain']}</td>
            <td>{data['total_ips']}</td>
            <td class="success"><strong>{data['success']}</strong></td>
            <td class="danger"><strong>{data['timeout']}</strong></td>
            <td class="warning"><strong>{data['blacklisted']}</strong></td>
            <td>
                <div>{data['success_rate']:.1f}%</div>
                <div class="progress-container">
                    <div class="progress-bar" style="width: {data['success_rate']}%"></div>
                </div>
                <span class="status-badge {status_class}">{status_text}</span>
            </td>
            <td>{format_time(data['test_time'])}</td>
        </tr>
        """
        domain_rows.append(row)
    
    # 生成超时IP行HTML
    timeout_rows = []
    for res in results:
        if res["timeout_ips"]:
            row = f"""
            <tr>
                <td>{res['domain']}</td>
                <td><span class="danger-badge"><i class="fas fa-times-circle"></i> {', '.join(res['timeout_ips'])}</span></td>
            </tr>
            """
            timeout_rows.append(row)
    
    # 准备替换字典
    replacements = {
        "timestamp": timestamp,
        "report_time": report_time,
        "current_year": current_year,
        "total_domains": str(total_domains),
        "total_ips": str(total_ips),
        "success_rate": success_rate,
        "total_test_time": format_time(total_test_time),
        "domain_rows": "\n".join(domain_rows),
        "timeout_rows": "\n".join(timeout_rows),
        "ping_retry": str(ping_retry),
        "api1_retry": str(api1_retry),
        "api2_retry": str(api2_retry),
        "cache_ttl": str(cache_ttl)
    }
    
    # 使用模板引擎替换变量
    template = Template(template)
    html_content = template.safe_substitute(replacements)
    
    # 写入HTML文件
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_file

def generate_text_summary(results, output_dir, html_report_path):
    """生成文本摘要并保存到文件"""
    # 统计数据
    total_domains = len(results)
    total_ips = 0
    total_success = 0
    total_timeout = 0
    total_blacklisted = 0
    total_test_time = 0
    
    for res in results:
        total_ips += res["total_ips"]
        total_success += len(res["success_ips"])
        total_timeout += len(res["timeout_ips"])
        total_blacklisted += len(res.get("blacklisted_ips", []))
        total_test_time += res.get("test_time", 0)
    
    # 计算整体成功率
    success_rate = total_success / total_ips * 100 if total_ips > 0 else 0
    overall_status = "成功" if success_rate > 90 else "警告" if success_rate > 70 else "失败"
    
    # 生成统计摘要
    summary = f"""
    ==================== 测试摘要 ====================
    测试域名数: {total_domains}
    总IP数量: {total_ips}
    总测试时间: {format_time(total_test_time)}
    -------------------------------------------------
    成功IP: {total_success} ({success_rate:.1f}%)
    超时IP: {total_timeout} ({total_timeout/total_ips*100:.1f}%)
    黑名单IP: {total_blacklisted} ({total_blacklisted/total_ips*100:.1f}%)
    -------------------------------------------------
    整体状态: {overall_status}
    =================================================
    """
    
    # 保存摘要到文件
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_file = os.path.join(output_dir, f"summary_{timestamp}.txt")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary.strip())
        f.write(f"\n\n详细HTML报告: {html_report_path}")
    
    return summary, summary_file

def generate_summary_report(results):
    """生成汇总报告"""
    # 生成HTML报告
    html_report = generate_html_report(
        results, 
        OUTPUT_DIR, 
        PING_RETRY, 
        API1_RETRY, 
        API2_RETRY, 
        CACHE_TTL_MINUTES
    )
    
    # 生成文本摘要
    summary, summary_file = generate_text_summary(
        results, 
        OUTPUT_DIR, 
        html_report
    )
    
    print(summary)
    print_info(f"报告已生成:")
    print_info(f"  - HTML报告: {html_report}")
    print_info(f"  - 文本摘要: {summary_file}")
    
    return html_report

def main():
    """主函数"""
    global start_time
    start_time = time.time()
    
    print_banner()
    clean_previous_results()  # 清理之前的结果文件
    load_cache()
    ip_blacklist = load_ip_blacklist()
    
    # 读取域名文件
    if not os.path.exists(DOMAINS_FILE):
        print_error(f"错误: 域名文件不存在 - {DOMAINS_FILE}")
        sys.exit(1)
    
    with open(DOMAINS_FILE, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    if not domains:
        print_error("错误: 域名文件为空")
        sys.exit(1)
    
    total_domains = len(domains)
    print_success(f"已加载域名: {total_domains}个")
    
    # 测试所有域名
    results = []
    
    print_header("开始测试域名")
    
    for idx, domain in enumerate(domains, 1):
        result = test_domain(domain, ip_blacklist, idx, total_domains)
        results.append(result)
    
    # 生成报告
    print_header("生成测试报告")
    generate_summary_report(results)
    
    # 保存缓存
    save_cache()
    
    total_time = time.time() - start_time
    print_success(f"\n所有域名测试完成! 总耗时: {format_time(total_time)}")
    print_success("测试完成 ✅")

def print_banner():
    """打印欢迎横幅"""
    terminal_width = shutil.get_terminal_size().columns
    title = "DNS测试系统"
    subtitle = "使用稳定大厂DNS API | 专业HTML报告 | 多平台支持"
    
    print("\n" + "=" * terminal_width)
    print(f"{TermColors.BOLD}{TermColors.HEADER}{title.center(terminal_width)}{TermColors.ENDC}")
    print(f"{TermColors.OKCYAN}{subtitle.center(terminal_width)}{TermColors.ENDC}")
    print("=" * terminal_width)
    
    print(f"\n{TermColors.BOLD}● 关键特性{TermColors.ENDC}")
    print(f"{TermColors.OKGREEN}✓ 多DNS提供商{TermColors.ENDC} - 使用Google, Quad9, AliDNS, DNSPod等大厂API")
    print(f"{TermColors.OKGREEN}✓ 专业HTML报告{TermColors.ENDC} - 现代化UI设计，响应式布局")
    print(f"{TermColors.OKGREEN}✓ 智能缓存系统{TermColors.ENDC} - 加速测试过程，减少重复检测")
    print(f"{TermColors.OKGREEN}✓ 全面测试{TermColors.ENDC} - 所有DNS记录完整检测")
    
    print(f"\n{TermColors.BOLD}● 配置参数{TermColors.ENDC}")
    print(f"{TermColors.OKBLUE}域名文件:{TermColors.ENDC} {DOMAINS_FILE}")
    print(f"{TermColors.OKBLUE}输出目录:{TermColors.ENDC} {OUTPUT_DIR}")
    print(f"{TermColors.OKBLUE}并发线程:{TermColors.ENDC} {THREADS}")
    print(f"{TermColors.OKBLUE}最大IP/域名:{TermColors.ENDC} {'无限制' if MAX_IPS_PER_DOMAIN == 0 else MAX_IPS_PER_DOMAIN}")
    print(f"{TermColors.OKBLUE}DNS解析:{TermColors.ENDC} 多API轮询机制")
    
    print("\n" + "=" * terminal_width)

if __name__ == "__main__":
    try:
        # 安装依赖检查
        try:
            import requests
            from collections import defaultdict
        except ImportError:
            print_error("缺少必要依赖，正在安装...")
            subprocess.run([sys.executable, "-m", "pip", "install", "requests"])
            import requests
            from collections import defaultdict
        
        main()
    except KeyboardInterrupt:
        print_error("\n\n测试被用户中断 ❌")
        save_cache()
        sys.exit(1)
    except Exception as e:
        print_error(f"\n发生错误: {str(e)}")
        save_cache()
        sys.exit(1)
