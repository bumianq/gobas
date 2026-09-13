# GoBAS

基于 [Nuclei](https://github.com/projectdiscovery/nuclei) v3 内核的入侵与攻击模拟（Breach and Attack Simulation, BAS）工具。

选取海量 POC 模板 → 绑定目标 → 自动执行攻击注入 → 依据响应特征给出**攻击拦截判定矩阵**（命中 / 被拦截 / 超时 / 不可达 / 未命中 / 错误），并沉淀完整攻击链流量供回溯分析。

提供三种使用入口：**CLI 命令行**、**REST API + SSE**、**Web 图形界面**（单二进制内嵌，零外部依赖）。

## 功能特性

- **POC 模板库**：聚合同步 190+ 社区 nuclei 模板源，数据库索引 + 引擎实载校验双保险，剔除不可执行模板（Interactsh 外带 / 凭据依赖 / 纯 code 脚本），保证扫描时 100% 可加载
- **目标基线探活**：HTTP 目标自动测基线（存活 / RTT / 状态码），TCP 目标 `ip:port` 直判端口开放；探活失败目标扫描时自动标 UNREACHABLE
- **攻击判定矩阵**：`HIT`（命中漏洞响应特征）/ `BLOCKED`（WAF 拦截指纹，如 403/405/418/429/501）/ `TIMEOUT` / `UNREACHABLE` / `MISS` / `ERROR`
- **攻击链流量还原**：请求/响应包按序落库（`task_traffic`），支持关键词特征搜索（WAF 拦截页指纹等）；另提供 socks5 镜像代理逐连接双向字节流（`dump`），覆盖 fuzz/多请求攻击链全部中间请求
- **人工判定修正**：机器自动判定不总可靠（WAF 指纹误判等），支持按结果行 / 按类别批量改写判定，自动判定原值留档可恢复
- **报告导出**：MD / JSON / CSV，含每 POC 的请求响应包与人工修正标记
- **流量出口代理**：扫描攻击流量可走自定义代理（http/https/socks5），便于中转与抓包调试
- **Web GUI**：POC 库 / 模板集 / 目标管理 / 扫描任务 / 结果与流量查看，全部支持批量操作与分页；扫描进度 SSE 实时推送
- **内建认证**：首次运行自动创建 `admin` + 随机密码（仅控制台展示一次），强制改密 + 会话管理，防爆破延迟；可关闭（纯内网脚本化场景）
- **绿色便携**：数据库与模板仓库固化为**相对路径**，随二进制目录整体拷贝即用；全静态编译（CGO_ENABLED=0），可在 macOS / Windows / Linux amd64 上无缝迁移

## 快速开始

> 本项目仅限授权范围内的安全评估使用。未经授权对目标进行探测与攻击属违法行为。

### 方式一：源码构建

```bash
# 本机（darwin/linux）
go build -o gobas ./cmd/gobas

# 交叉编译（需在任意平台执行）
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/gobas-windows-amd64.exe ./cmd/gobas
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/gobas-linux-amd64    ./cmd/gobas
```

### 方式二：直接运行

二进制下载/编译后可直接执行（数据目录默认 = 程序所在目录，所有数据就地生成）：

```bash
./gobas version                      # 版本
./gobas serve                        # 启动服务（首次运行打印 admin 初始密码）
```

### 前置条件

- **git**：`gobas sync` 同步 POC 源仓库依赖本机 `git` 命令（clone/pull），未安装时 POC 同步将失败；其余功能（索引已有模板、目标探活、扫描、报告导出）不依赖外部工具
- **网络**：POC 源同步与部分带外（Out-of-Band）POC 需要访问外网；纯粹针对内网的扫描不受影响

### 首次运行（Web 方式）

1. 执行 `./gobas serve`，浏览器访问 http://127.0.0.1:8080
2. 用控制台打印的 `admin` + 随机初始密码登录，登录后**强制修改密码**
3. 忘记密码：`./gobas auth reset-password --username admin`

## 典型流程（CLI）

```bash
# 1. 同步 POC 源仓库（git clone/pull，清单见 sources.yaml）
./gobas sync --workers 4

# 2. 建立 POC 索引（解析模板、引擎实载校验、去重）
./gobas pocs index

# 3. 添加目标（自动基线探活）
./gobas target add http://192.168.1.10:8080        # HTTP 目标
./gobas target add 192.168.1.20:6379                # TCP 目标（仅执行 network 协议 POC）
./gobas target list                                 # 查看探活结果

# 4. 执行攻击模拟
./gobas scan run --severity critical                # 全部存活目标 × critical POC
./gobas scan run --targets 1,2 --pocs 23,45 --name "专项"   # 指定目标与 POC
./gobas scan run --dry-run                          # 只预览矩阵不执行

# 5. 查看结果与流量
./gobas scan results 1 --verdict HIT               # 命中列表（含人工修正标记 ✎）
./gobas scan traffic 1 --full                      # 完整请求/响应包
./gobas scan traffic 1 --search "Blocked by WAF"   # 指纹搜索流量
./gobas scan dump 1 --full                         # 镜像代理双向字节流（完整攻击链）

# 6. 人工修正判定 + 导出报告
./gobas scan verdict 1 --from MISS --to BLOCKED --apply   # 批量修正
./gobas scan verdict 1 --ids 12,13 --to ""                # 恢复自动判定
./gobas scan report 1 --format md|json|csv                # 导出报告
```

## CLI 命令参考

| 命令 | 说明 |
|---|---|
| `gobas sync [--import-csv repo.csv] [--workers 4]` | 同步 POC 源仓库（git clone/pull） |
| `gobas pocs index` | 解析克隆目录全部模板并重建索引 |
| `gobas pocs list [--severity] [--tag] [--search] [--limit]` | 按条件查询 POC 库 |
| `gobas pocs stats` | POC 库统计（按严重度/协议/来源 TOP10） |
| `gobas pocs show <id>` | 查看单个 POC 详情 |
| `gobas target add <url>... [--name]` | 添加目标（自动基线探活） |
| `gobas target list` / `probe [id...]` / `remove <id>` | 目标列表 / 重新探活 / 删除 |
| `gobas scan run [--targets] [--pocs] [--severity] [--tag] [--search] [--max] [--include-dead] [--proxy] [--dry-run]` | 启动攻击模拟并实时输出进度 |
| `gobas scan list` / `status <id>` / `cancel <id>` / `delete <id...>` | 扫描历史 / 详情 / 取消 / 删除 |
| `gobas scan results <id> [--verdict]` | 扫描结果列表 |
| `gobas scan traffic <id> [--full] [--poc] [--target] [--search] [--field] [--limit]` | 请求/响应流量记录 |
| `gobas scan dump <id> [--full] [--limit]` | 镜像连接流水（完整攻击链字节流） |
| `gobas scan verdict <id> [--ids] [--from] [--to] [--apply]` | 人工修正判定 |
| `gobas scan report <id> [--format md\|json\|csv]` | 导出报告（含人工修正标记） |
| `gobas serve [--addr]` | 启动 REST API + SSE + Web GUI |
| `gobas auth reset-password [--username] [--password]` | 管理员密码重置（踢所有会话 + 强制改密） |
| `gobas version` | 版本信息 |

全局参数：`--config <path>`（配置文件，缺省用内置默认值）、`--proxy <url>`（覆盖出站代理）、`--no-proxy`（强制直连）。

## Web GUI

`gobas serve` 后浏览器打开首页即进入（SPA 单页，hash 路由，内嵌进二进制无外部静态文件）。

- **POC 库**：列表/搜索/筛选，详情可看 YAML 原文（编辑/删除仅对自定义 POC 开放）
- **POC 模板集**：自定义集合并批量添加/移除 POC，内置 Top100 默认集（HTTP 78 + TCP 22，全攻击载荷直达）
- **目标管理**：批量添加/探活/删除，存活状态一目了然
- **扫描任务**：新建扫描（目标 × POC 矩阵、流量出口代理可选）、SSE 实时进度、结果维度下钻（判定 / 流量 / 人工修正）
- **扫描详情**：结果列表批量改判定、流量查看与特征搜索、报告导出
- **认证**：登录 / 改密 / 退出，未登录自动跳转登录页（认证关闭时自动跳过）

## REST API

基础路径 `/api/v1`，Cookie 会话认证（`gobas_session`，HttpOnly）。认证关闭（`server.auth_enabled=false`）时全部放行。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` `/auth/logout` `/auth/change-password` | 登录 / 登出 / 改密 |
| GET | `/auth/status` `/healthz` | 登录引导状态 / 健康检查 |
| POST | `/sync` | 同步 POC 源（GET `/sync/events` SSE、`/sync/status`） |
| GET/POST | `/pocs` `/pocs/index` `/pocs/stats` `/pocs/{id}` `/pocs/{id}/content` | POC 库查询 / 重建索引（含 SSE 进度）/ 统计 / 详情 / YAML 原文 |
| CRUD | `/pocs/custom` | 自定义 POC 增改删 |
| CRUD | `/poc-sets` 及 `/poc-sets/{id}/pocs` | POC 模板集管理 |
| GET/POST | `/targets` `/targets/probe` `DELETE /targets/{id}` | 目标管理 / 批量探活 / 删除 |
| POST | `/scans` | 创建扫描（body：targets/poc_ids/poc_filter/proxy/name） |
| GET | `/scans` `/scans/{id}` `/scans/{id}/results` | 扫描历史（分页）/ 详情 / 结果 |
| POST | `/scans/{id}/results/verdict` | 人工修正判定（单条/批量） |
| GET | `/scans/{id}/traffic` `/scans/{id}/dump` | 请求响应流量（含 search/field 过滤）/ 镜像连接流水 |
| GET | `/scans/{id}/events` | 扫描进度 SSE |
| POST/DELETE | `/scans/{id}/cancel` `/scans/{id}` | 取消 / 删除扫描（级联删结果与流量） |
| GET | `/scans/{id}/report` | 导出报告 md/json/csv |

## 配置说明

默认配置编译内置于二进制；用 `--config <path>` 指定 YAML 文件时，仅覆盖文件中出现的字段，其余用默认值。数据目录（`workspace`）默认为**程序所在目录**，所有路径均为相对路径，目录整体拷贝即可迁移。

```yaml
workspace: ""                    # 数据目录（空 = 程序所在目录，绿色便携）
network:
  proxy: "http://127.0.0.1:7897" # 仅用于 POC 源 git 同步
scan:
  timeout_sec: 10                # 单请求超时（秒）
  retries: 2                     # 失败重试
  rate_limit_per_s: 150          # 全局限速（请求/秒），0 不限
  max_pocs: 500                  # 单次扫描 POC 数量上限（防内存爆炸）
  traffic_save: true             # 是否记录任务流量
  traffic_max_bytes: 65536       # 单个包字段截断上限（字节）
verdict:
  blocked_statuses: [403, 405, 418, 429, 501]  # 视为被拦截的 HTTP 状态码
server:
  addr: "127.0.0.1:8080"         # 监听地址
  auth_enabled: true             # 登录认证开关（内网纯脚本可关）
  session_ttl_hours: 24          # 会话有效期
```

扫描级代理用 `--proxy` 或 GUI 新建扫描时指定（仅作用于引擎攻击流量，支持 http/https/socks5；空 = 直连）。

## 判定矩阵

| 判定 | 含义 | 典型特征 |
|---|---|---|
| `HIT` | 命中漏洞响应特征 | matcher 匹配成功且有实体响应 |
| `BLOCKED` | 被安全设备拦截 | 命中配置的拦截状态码（403/405/418/429/501）或拦截指纹 |
| `TIMEOUT` | 请求超时 | 超时时间内无响应 |
| `UNREACHABLE` | 目标不可达 | 端口关闭 / 拒绝连接 / 无路由 |
| `MISS` | 未命中 | 正常响应但无漏洞特征 |
| `ERROR` | 执行异常 | 参数错误、引擎拒绝加载等 |

## 目录结构

```
├── cmd/gobas/          # 程序入口
├── cmd/                # CLI 命令（sync/pocs/target/scan/serve/auth）
├── internal/
│   ├── config/         # 配置加载与默认值
│   ├── source/         # POC 源仓库同步（git clone/pull）
│   ├── pocs/           # POC 模板解析 / 索引 / 执行性预过滤
│   ├── target/         # 目标管理与基线探活（HTTP/TCP）
│   ├── engine/         # nuclei 引擎封装（两批矩阵执行 / 流量提取 / 事件捕获）
│   ├── verdict/        # 攻击判定逻辑
│   ├── store/          # SQLite 存取（migrations 含多轮迁移 v1~v13）
│   ├── report/         # 报告导出（md/json/csv）
│   ├── service/        # 业务层（CLI 与 API 双入口）
│   └── server/         # REST API + SSE + Web GUI（嵌入式单文件前端）
├── sources.yaml        # POC 源仓库清单（190+）
├── clone-templates/    # 克隆的模板仓库（磁盘存储，DB 只存元数据）
├── custom-pocs/        # 人工添加的 POC 模板
├── gobas.db            # SQLite 数据库（程序目录自动生成）
└── dist/               # 交叉编译产物
```

## 技术栈

- Go 1.26 + [nuclei v3](https://github.com/projectdiscovery/nuclei)（引擎内核）
- [modernc.org/sqlite](https://gitlab.com/cznic/sqlite)（纯 Go SQLite，`CGO_ENABLED=0` 静态编译）
- [chi](https://github.com/go-chi/chi)（HTTP 路由）+ SSE 实时推送
- [cobra](https://github.com/spf13/cobra)（CLI）
- 前端：原生 HTML/CSS/JS，`go:embed` 内嵌，独立运行零外部文件

## 安全与合规

- **仅限授权评估**：请在获得书面授权的目标范围内使用
- 默认配置本地监听（127.0.0.1:8080），如需对外提供服务请自行评估并收紧认证
- 首次运行自动生成随机管理员密码且仅展示一次，务必立即改密