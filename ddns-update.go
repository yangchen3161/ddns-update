// ddnsc-update.go - A DDNS client.
//go:build release

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Windows API
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")

	procAllocConsole     = kernel32.NewProc("AllocConsole")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
)

type DDNSClient struct {
	logger       *log.Logger                  // 8字节（64位系统上的指针）
	config       map[string]map[string]string // 8字节
	checkPeriod  int                          // 8字节
	showConsole  bool                         // 1字节
	ipv4CheckURL string                       // 16字节
	ipv6CheckURL string                       // 16字节
}

type updateTask struct {
	section  string
	hostname string
}

func showConsoleWindow() {
	// 分配新的控制台
	procAllocConsole.Call()
	// 获取控制台窗口句柄
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		// SW_SHOW = 5
		procShowWindow.Call(hwnd, 5)
	}
}

func hideConsoleWindow() {
	// 获取控制台窗口句柄
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		// SW_HIDE = 0
		procShowWindow.Call(hwnd, 0)
	}
}

// 添加配置文件的结构体定义
type Config struct {
	General struct {
		Period  int    `json:"period"`
		IPv4API string `json:"ipv4-api"`
		IPv6API string `json:"ipv6-api"`
	} `json:"general"`
	Domains map[string]DomainConfig `json:"domains"`
}

type DomainConfig struct {
	Hostname   string `json:"hostname"`
	DDNSServer string `json:"ddns-server"`
	DDNSPath   string `json:"ddns-path"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

func NewDDNSClient(configFile string, showConsole bool) (*DDNSClient, error) {
	client := &DDNSClient{
		config:      make(map[string]map[string]string),
		showConsole: showConsole,
	}

	// 先设置日志系统
	client.setupLogging()
	client.logger.Printf("INFO - 开始初始化DDNS客户端...")

	// 如果需要显示控制台，立即调用
	if showConsole {
		showConsoleWindow()
		client.logger.Printf("INFO - 控制台窗口已启用")
	}

	// 加载配置文件
	if err := client.loadConfig(configFile); err != nil {
		return nil, fmt.Errorf("加载配置文件失败: %v", err)
	}
	client.logger.Printf("INFO - 配置文件加载成功")

	// 从配置文件读取常规配置
	if general, ok := client.config["general"]; ok {
		if period, ok := general["period"]; ok {
			if p, err := strconv.Atoi(period); err == nil {
				client.checkPeriod = p
				client.logger.Printf("INFO - 检查周期设置为 %d 秒", p)
			}
		}
		client.ipv4CheckURL = general["ipv4-api"]
		client.ipv6CheckURL = general["ipv6-api"]
		client.logger.Printf("INFO - IPv4 API: %s", client.ipv4CheckURL)
		client.logger.Printf("INFO - IPv6 API: %s", client.ipv6CheckURL)
	}

	return client, nil
}

func (c *DDNSClient) loadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 初始化配置映射
	c.config = make(map[string]map[string]string)
	var currentSection string

	// 按行读取配置文件
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// 去除空白字符
		line = strings.TrimSpace(line)

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// 处理节名
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			c.config[currentSection] = make(map[string]string)
			continue
		}

		// 处理键值对
		if currentSection != "" {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				c.config[currentSection][key] = value
			}
		}
	}

	return nil
}

func (c *DDNSClient) setupLogging() {
	// 创建日志文件
	logFile, err := os.OpenFile("ddns-update.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	// 如果需要显示控制台，使用多重输出
	var writers []io.Writer
	writers = append(writers, logFile)
	if c.showConsole {
		writers = append(writers, os.Stderr)
	}

	// 创建多输出writer
	multiWriter := io.MultiWriter(writers...)

	// 设置日志格式和输出
	c.logger = log.New(multiWriter, "", log.Ldate|log.Ltime)
}

func (c *DDNSClient) getCurrentIP(isIPv6 bool) string {
	url := c.ipv4CheckURL
	if isIPv6 {
		url = c.ipv6CheckURL
	}

	c.logger.Printf("INFO - 正在从 %s 获取%s地址...", url, map[bool]string{true: "IPv6", false: "IPv4"}[isIPv6])

	resp, err := http.Get(url)
	if err != nil {
		c.logger.Printf("ERROR - 获取IP地址失败: %v", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Printf("ERROR - 读取响应失败: %v", err)
		return ""
	}

	content := strings.TrimSpace(string(body))
	c.logger.Printf("INFO - 获取到原始响应内容: %s", content)

	// IP地址匹配模式
	var ipPattern string
	if isIPv6 {
		ipPattern = `([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])`
	} else {
		ipPattern = `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`
	}

	re := regexp.MustCompile(ipPattern)
	match := re.FindString(content)

	if match != "" {
		c.logger.Printf("INFO - 成功提取到%s地址: %s", map[bool]string{true: "IPv6", false: "IPv4"}[isIPv6], match)
		return match
	}

	c.logger.Printf("ERROR - 在响应内容中未找到有效的%s地址", map[bool]string{true: "IPv6", false: "IPv4"}[isIPv6])
	return ""
}

func (c *DDNSClient) getDomainIP(domain string, isIPv6 bool) string {
	// 这里需要使用 net 包的 DNS 查询功能
	var recordType string
	if isIPv6 {
		recordType = "AAAA"
	} else {
		recordType = "A"
	}

	ips, err := net.LookupIP(domain)
	if err != nil {
		c.logger.Printf("ERROR - 获取域名%s的%s记录失败: %v", domain, recordType, err)
		return ""
	}

	for _, ip := range ips {
		if isIPv6 {
			if ip.To4() == nil {
				return ip.String()
			}
		} else {
			if ip.To4() != nil {
				return ip.String()
			}
		}
	}

	return ""
}

func (c *DDNSClient) updateDDNS(section string, ipv4, ipv6 string) error {
	if section == "" {
		return fmt.Errorf("section 不能为空")
	}

	hostname := c.config[section]["hostname"]
	hasIPv4API := c.config["general"]["ipv4-api"] != ""
	hasIPv6API := c.config["general"]["ipv6-api"] != ""

	updateMode := c.config[section]["update-ip"]
	if updateMode == "" {
		// 根据可用的API决定默认更新模式
		if hasIPv4API && hasIPv6API {
			updateMode = "both"
		} else if hasIPv4API {
			updateMode = "ipv4"
		} else if hasIPv6API {
			updateMode = "ipv6"
		}
	}

	// 根据API可用性和更新模式过滤IP
	if !hasIPv4API || (updateMode != "ipv4" && updateMode != "both") {
		ipv4 = ""
	}
	if !hasIPv6API || (updateMode != "ipv6" && updateMode != "both") {
		ipv6 = ""
	}

	if ipv4 == "" && ipv6 == "" {
		return fmt.Errorf("没有需要更新的IP地址")
	}

	// 获取配置
	server := c.config[section]["ddns-server"]
	path := c.config[section]["ddns-path"]
	username := c.config[section]["username"]
	password := c.config[section]["password"]

	// 检查配置完整性
	if server == "" || path == "" || hostname == "" || username == "" || password == "" {
		return fmt.Errorf("配置信息不完整")
	}

	c.logger.Printf("INFO - 配置信息验证完成: 服务器=%s, 主机名=%s", server, hostname)

	// 替换变量
	replacements := map[string]string{
		"%u":  username,
		"%p":  password,
		"%h":  hostname,
		"%i4": ipv4,
		"%i6": ipv6,
	}

	c.logger.Printf("INFO - 原始URL路径: %s", path)
	for key, value := range replacements {
		if strings.Contains(path, key) {
			c.logger.Printf("INFO - 替换参数 %s -> %s", key, value)
			path = strings.ReplaceAll(path, key, value)
		}
	}

	// 构建完整URL
	url := fmt.Sprintf("https://%s%s", server, path)
	c.logger.Printf("INFO - 正在发送更新请求到: %s", url)

	// 发送请求
	resp, err := http.Get(url)
	if err != nil {
		c.logger.Printf("ERROR - 发送请求时发生错误: %v", err)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Printf("ERROR - 读取响应失败: %v", err)
		return err
	}

	c.logger.Printf("INFO - 域名 %s 收到响应 - 状态码: %d", hostname, resp.StatusCode)
	c.logger.Printf("INFO - 域名 %s 响应内容: %s", hostname, strings.TrimSpace(string(body)))

	if resp.StatusCode == 200 {
		if ipv4 != "" {
			c.logger.Printf("INFO - 域名 %s 更新成功!，IPv4更新为: %s", hostname, ipv4)
		}
		if ipv6 != "" {
			c.logger.Printf("INFO - 域名 %s 更新成功!，IPv6更新为: %s", hostname, ipv6)
		}
	} else {
		return fmt.Errorf("更新失败 - HTTP状态码: %d", resp.StatusCode)
	}

	return nil
}

func (c *DDNSClient) Run() {
	c.logger.Printf("INFO - DDNS客户端启动")

	// 记录API配置情况
	hasIPv4API := c.config["general"]["ipv4-api"] != ""
	hasIPv6API := c.config["general"]["ipv6-api"] != ""

	if !hasIPv4API && !hasIPv6API {
		c.logger.Printf("ERROR - 配置文件中未找到任何IP检查API")
		return
	}

	for {
		var currentIPv4, currentIPv6 string

		// 只在配置了IPv4 API时获取IPv4地址
		if hasIPv4API {
			c.logger.Printf("INFO - 正在获取本机IPv4地址...")
			currentIPv4 = c.getCurrentIP(false)
			if currentIPv4 != "" {
				c.logger.Printf("INFO - 当前IPv4地址: %s", currentIPv4)
			} else {
				c.logger.Printf("WARN - 未能获取IPv4地址")
			}
		}

		// 只在配置了IPv6 API时获取IPv6地址
		if hasIPv6API {
			c.logger.Printf("INFO - 正在获取本机IPv6地址...")
			currentIPv6 = c.getCurrentIP(true)
			if currentIPv6 != "" {
				c.logger.Printf("INFO - 当前IPv6地址: %s", currentIPv6)
			} else {
				c.logger.Printf("WARN - 未能获取IPv6地址")
			}
		}

		// 检查是否获取到任何IP地址
		if (!hasIPv4API || currentIPv4 != "") && (!hasIPv6API || currentIPv6 != "") {
			c.logger.Printf("INFO - IP地址检查完成")
		} else {
			c.logger.Printf("ERROR - 无法获取配置的IP地址")
			if c.checkPeriod == 0 {
				c.logger.Printf("INFO - 由于period=0，程序将退出")
				break
			}
			c.logger.Printf("INFO - 将在 %d 秒后重试...", c.checkPeriod)
			time.Sleep(time.Duration(c.checkPeriod) * time.Second)
			continue
		}

		var updateTasks []updateTask

		for section := range c.config {
			if section == "general" {
				continue
			}

			hostname := c.config[section]["hostname"]
			updateMode := c.config[section]["update-ip"]
			if updateMode == "" {
				// 根据可用的API决定默认更新模式
				if hasIPv4API && hasIPv6API {
					updateMode = "both"
				} else if hasIPv4API {
					updateMode = "ipv4"
				} else if hasIPv6API {
					updateMode = "ipv6"
				}
				c.logger.Printf("INFO - 域名 %s 未配置update-ip，根据可用API默认使用%s模式", hostname, updateMode)
			}

			c.logger.Printf("INFO - 正在检查域名 %s 的IP状态（更新模式: %s）...", hostname, updateMode)

			needUpdate := false
			var domainIPv4, domainIPv6 string

			// 只在有IPv4 API且更新模式包含IPv4时检查
			if hasIPv4API && (updateMode == "ipv4" || updateMode == "both") {
				if currentIPv4 != "" {
					domainIPv4 = c.getDomainIP(hostname, false)
					if domainIPv4 != currentIPv4 {
						c.logger.Printf("INFO - %s IPv4需要更新: %s -> %s", hostname, domainIPv4, currentIPv4)
						needUpdate = true
					} else {
						c.logger.Printf("INFO - %s IPv4无需更新 (当前: %s)", hostname, domainIPv4)
					}
				}
			}

			// 只在有IPv6 API且更新模式包含IPv6时检查
			if hasIPv6API && (updateMode == "ipv6" || updateMode == "both") {
				if currentIPv6 != "" {
					domainIPv6 = c.getDomainIP(hostname, true)
					if domainIPv6 != currentIPv6 {
						c.logger.Printf("INFO - %s IPv6需要更新: %s -> %s", hostname, domainIPv6, currentIPv6)
						needUpdate = true
					} else {
						c.logger.Printf("INFO - %s IPv6无需更新 (当前: %s)", hostname, domainIPv6)
					}
				}
			}

			if needUpdate {
				updateTasks = append(updateTasks, updateTask{section, hostname})
			}
		}

		// 使用WaitGroup进行并发更新
		var wg sync.WaitGroup
		for _, task := range updateTasks {
			wg.Add(1)
			go func(section, hostname string) {
				defer wg.Done()
				c.logger.Printf("INFO - 准备更新域名 %s", hostname)
				err := c.updateDDNS(section, currentIPv4, currentIPv6)
				if err != nil {
					c.logger.Printf("ERROR - 更新域名 %s 失败: %v", hostname, err)
				}
			}(task.section, task.hostname)
		}
		wg.Wait()

		if c.checkPeriod == 0 {
			c.logger.Printf("INFO - 配置period=0，完成一次性更新，程序将退出")
			break
		}

		c.logger.Printf("INFO - 本轮检查完成，等待 %d 秒后进行下一次检查...", c.checkPeriod)
		time.Sleep(time.Duration(c.checkPeriod) * time.Second)
	}
}

func (c *DDNSClient) validateConfig() error {
	if general, ok := c.config["general"]; ok {
		if general["ipv4-api"] == "" && general["ipv6-api"] == "" {
			return fmt.Errorf("配置文件中必须至少指定一个 IP 检查 API (ipv4-api 或 ipv6-api)")
		}
	} else {
		return fmt.Errorf("配置文件中缺少 [general] 节")
	}
	return nil
}

func main() {
	noconsole := flag.Bool("noconsole", false, "不显示控制台窗口")
	flag.Parse()

	if *noconsole {
		hideConsoleWindow()
	}

	// 设置全局日志输出
	if !*noconsole {
		log.SetOutput(os.Stderr)
	}
	log.SetFlags(log.Ldate | log.Ltime)
	log.Println("程序启动...")

	// 检查配置文件是否存在
	if _, err := os.Stat("config.ini"); os.IsNotExist(err) {
		log.Printf("错误: 配置文件 config.ini 不存在")
		if !*noconsole {
			log.Println("按回车键退出...")
			fmt.Scanln()
		}
		os.Exit(1)
	}

	client, err := NewDDNSClient("config.ini", !*noconsole)
	if err != nil {
		log.Printf("错误: 创建DDNS客户端失败: %v", err)
		if !*noconsole {
			log.Println("按回车键退出...")
			fmt.Scanln()
		}
		os.Exit(1)
	}

	// 添加配置验证
	if err := client.validateConfig(); err != nil {
		log.Printf("错误: 配置验证失败: %v", err)
		log.Printf("请检查配置文件中的 [general] 节是否包含 ipv4-api 或 ipv6-api 配置")
		if !*noconsole {
			log.Println("按回车键退出...")
			fmt.Scanln()
		}
		os.Exit(1)
	}

	// 添加错误恢复
	defer func() {
		if r := recover(); r != nil {
			log.Printf("程序发生严重错误: %v", r)
			if !*noconsole {
				log.Println("按回车键退出...")
				fmt.Scanln()
			}
		}
	}()

	client.Run()

	// 正常退出时直接结束，不等待用户输入
	log.Println("程序执行完成")
}
