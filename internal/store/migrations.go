package store

import (
	"fmt"
)

// migrations 版本化 DDL，索引从 0 开始，user_version 递增。
var migrations = []string{
	// v1: 初始表结构
	`
CREATE TABLE IF NOT EXISTS pocs (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id    TEXT    NOT NULL,
  name           TEXT    NOT NULL DEFAULT '',
  authors        TEXT    NOT NULL DEFAULT '',
  severity       TEXT    NOT NULL DEFAULT '',
  tags           TEXT    NOT NULL DEFAULT '',
  cve_ids        TEXT    NOT NULL DEFAULT '',
  cnvd_ids       TEXT    NOT NULL DEFAULT '',
  cwe_ids        TEXT    NOT NULL DEFAULT '',
  cvss_score     REAL    NOT NULL DEFAULT 0,
  protocols      TEXT    NOT NULL DEFAULT '[]',
  has_interactsh INTEGER NOT NULL DEFAULT 0,
  file_path      TEXT    NOT NULL,
  content_hash   TEXT    NOT NULL UNIQUE,
  file_size      INTEGER NOT NULL DEFAULT 0,
  source_repo    TEXT    NOT NULL DEFAULT '',
  is_official    INTEGER NOT NULL DEFAULT 0,
  indexed_at     TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_pocs_template_id ON pocs(template_id);
CREATE INDEX IF NOT EXISTS idx_pocs_severity    ON pocs(severity);

CREATE TABLE IF NOT EXISTS targets (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT    NOT NULL DEFAULT '',
  url             TEXT    NOT NULL UNIQUE,
  alive           INTEGER NOT NULL DEFAULT 0,
  baseline_status INTEGER NOT NULL DEFAULT 0,
  baseline_rtt_ms INTEGER NOT NULL DEFAULT 0,
  baseline_error  TEXT    NOT NULL DEFAULT '',
  last_probe_at   TEXT    NOT NULL DEFAULT '',
  created_at      TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS scans (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  name              TEXT    NOT NULL DEFAULT '',
  status            TEXT    NOT NULL DEFAULT 'running',
  poc_filter        TEXT    NOT NULL DEFAULT '{}',
  target_count      INTEGER NOT NULL DEFAULT 0,
  poc_count         INTEGER NOT NULL DEFAULT 0,
  total_tasks       INTEGER NOT NULL DEFAULT 0,
  done_tasks        INTEGER NOT NULL DEFAULT 0,
  hit_count         INTEGER NOT NULL DEFAULT 0,
  blocked_count     INTEGER NOT NULL DEFAULT 0,
  timeout_count     INTEGER NOT NULL DEFAULT 0,
  unreachable_count INTEGER NOT NULL DEFAULT 0,
  miss_count        INTEGER NOT NULL DEFAULT 0,
  error_count       INTEGER NOT NULL DEFAULT 0,
  started_at        TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
  finished_at       TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scan_targets (
  scan_id   INTEGER NOT NULL REFERENCES scans(id)   ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  PRIMARY KEY (scan_id, target_id)
);

CREATE TABLE IF NOT EXISTS results (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id        INTEGER NOT NULL,
  poc_id           INTEGER NOT NULL,
  verdict          TEXT    NOT NULL,
  matched_at       TEXT    NOT NULL DEFAULT '',
  matcher_name     TEXT    NOT NULL DEFAULT '',
  response_status  INTEGER NOT NULL DEFAULT 0,
  response_time_ms INTEGER NOT NULL DEFAULT 0,
  error_text       TEXT    NOT NULL DEFAULT '',
  evidence         TEXT    NOT NULL DEFAULT '',
  created_at       TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_results_pair ON results(scan_id, target_id, poc_id);
`,
	// v2: POC 模板集（自由组装的 POC 分组，供攻击模拟复用）
	`
CREATE TABLE IF NOT EXISTS poc_sets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL UNIQUE,
  description TEXT    NOT NULL DEFAULT '',
  created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS poc_set_items (
  set_id   INTEGER NOT NULL REFERENCES poc_sets(id) ON DELETE CASCADE,
  poc_id   INTEGER NOT NULL REFERENCES pocs(id)     ON DELETE CASCADE,
  added_at TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
  PRIMARY KEY (set_id, poc_id)
);
CREATE INDEX IF NOT EXISTS idx_poc_set_items_poc ON poc_set_items(poc_id);
`,
	// v3: scans 表记录失败原因（引擎错误/异常信息，GUI 展示用）
	`ALTER TABLE scans ADD COLUMN error_text TEXT NOT NULL DEFAULT '';`,
	// v4: POC 自包含标记（-1=未检测 0=否 1=是）。
	// 自包含模板（cloud/enum 等）不对扫描目标发请求，扫描时跳过；
	// 存量行默认 -1，由扫描流程懒检测回写，新索引直接写入。
	`ALTER TABLE pocs ADD COLUMN self_contained INTEGER NOT NULL DEFAULT -1;`,
	// v5: POC 签名验证状态（0=未验证 1=已通过官方签名验证）。
	// code 协议模板未通过签名验证会被 nuclei 无条件拒绝加载，
	// 扫描时由本地签名器自动重签，POC 库展示用此字段标记可执行性。
	`ALTER TABLE pocs ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;`,
	// v6: code 协议模板使用的语言引擎（CSV，如 "php,python3"）。
	// 引擎加载时需检查本地是否安装了对应语言解释器，未安装则跳过。
	`ALTER TABLE pocs ADD COLUMN code_engines TEXT NOT NULL DEFAULT '';`,
	// v7: 任务流量记录——每个 (POC,目标) 任务实际发送的请求包与收到的响应包。
	// seq 为扫描内事件顺序（锁内分配，锁外批量落库时 rowid 不可靠）；
	// 同一任务多事件（多请求模板/攻击链）逐行保留，seq 保序即可还原攻击链。
	`
CREATE TABLE IF NOT EXISTS task_traffic (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id      INTEGER NOT NULL,
  poc_id         INTEGER NOT NULL,
  seq            INTEGER NOT NULL,
  protocol       TEXT    NOT NULL DEFAULT '',
  matched        INTEGER NOT NULL DEFAULT 0,
  status         INTEGER NOT NULL DEFAULT 0,
  request        TEXT    NOT NULL DEFAULT '',
  response       TEXT    NOT NULL DEFAULT '',
  req_truncated  INTEGER NOT NULL DEFAULT 0,
  resp_truncated INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_seq  ON task_traffic(scan_id, seq);
CREATE INDEX IF NOT EXISTS idx_traffic_pair ON task_traffic(scan_id, poc_id, target_id);
`,
	// v8: 人工修正判定——机器自动判定不一定准确（WAF 指纹误判等），
	// 支持人工修改结果类别。修改时直接更新 verdict 列（所有读取路径
	// 天然同步：结果列表/判定矩阵/报告导出），auto_verdict 回填机器
	// 原始判定用于恢复，manual_at 标记人工修改时间（空=未修改）。
	`
ALTER TABLE results ADD COLUMN auto_verdict TEXT NOT NULL DEFAULT '';
ALTER TABLE results ADD COLUMN manual_at TEXT NOT NULL DEFAULT '';
`,
	// v9: 扫描流量出口代理——发起攻击模拟时可指定代理（自定义）或直连（空）。
	// 代理仅作用于本次扫描的攻击流量（指向 Burp/WAF 模拟代理观察拦截行为），
	// 不影响探活与 POC 源同步；空 = 直连。
	`ALTER TABLE scans ADD COLUMN proxy TEXT NOT NULL DEFAULT '';`,
	// v10: 逐连接流量镜像——内置 socks5 镜像代理记录的扫描原始连接流水
	// （每条连接一行：目标地址 + 双向字节流）。与 task_traffic（事件级
	// 最终请求）互补：fuzz 字典、多请求攻击链的全部中间请求在这里完整可见。
	// 代理层无法区分连接归属的 POC，仅记录 scan 级顺序流水（seq 保序）。
	`
CREATE TABLE IF NOT EXISTS scan_traffic_dump (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  seq          INTEGER NOT NULL,
  addr         TEXT    NOT NULL,
  started_at   TEXT    NOT NULL,
  duration_ms  INTEGER NOT NULL DEFAULT 0,
  client_data  TEXT    NOT NULL DEFAULT '',
  server_data  TEXT    NOT NULL DEFAULT '',
  client_len   INTEGER NOT NULL DEFAULT 0,
  server_len   INTEGER NOT NULL DEFAULT 0,
  client_trunc INTEGER NOT NULL DEFAULT 0,
  server_trunc INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dump_seq ON scan_traffic_dump(scan_id, seq);
`,

	// v11: 历史时间数据校正 UTC → 本地时间。
	// 此前所有时间列由 datetime('now')（UTC）或 Go time.Now().UTC() 写入，
	// 对 UTC+8 等东八区用户显示恒差 8 小时。本次迁移将存量数据按当前
	// 系统时区偏移（动态计算，不硬编码 +8h）平移到本地时间；此后新写入
	// 由代码显式传本地时间（已存在的表 DEFAULT 已固化为 UTC，不能依赖）。
	// 注意：只对可解析的时间值生效，空串/NULL 不受影响（datetime 返回 NULL）。
	`
UPDATE scans SET
  started_at  = datetime(started_at,  (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds'),
  finished_at = datetime(finished_at, (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds')
WHERE started_at != '';
UPDATE results SET
  created_at = datetime(created_at,  (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds');
UPDATE task_traffic SET
  created_at = datetime(created_at,  (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds');
UPDATE scan_traffic_dump SET
  started_at = datetime(started_at,   (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds');
UPDATE targets SET
  created_at   = datetime(created_at,   (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds'),
  last_probe_at = datetime(last_probe_at, (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds')
WHERE created_at != '';
UPDATE pocs SET
  indexed_at = datetime(indexed_at, (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds');
UPDATE poc_sets SET
  created_at = datetime(created_at, (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds');
UPDATE poc_set_items SET
  added_at = datetime(added_at,    (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds');
UPDATE results SET
  manual_at = datetime(manual_at,  (strftime('%s','now','localtime') - strftime('%s','now')) || ' seconds')
WHERE manual_at != '';
`,

	// v12: 人工自定义 POC 标记——用户手工添加的模板独立于自动拉取源，
	// 模板文件存于 workspace/custom-pocs/（git 同步不触碰），重建索引只清除
	// 自动拉取行（is_custom=0），人工行及其模板集引用在重建后原样保留。
	`ALTER TABLE pocs ADD COLUMN is_custom INTEGER NOT NULL DEFAULT 0;`,

	// v13: 认证——用户与会话。首次运行创建 admin（随机初始密码，只打印到
	// 控制台不落库），登录后需强制改密（must_change_password=1）；
	// sessions 仅存 token 的 SHA-256 哈希，过期由服务端 TTL 判定。
	`
CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  username             TEXT    NOT NULL UNIQUE,
  password_hash        TEXT    NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at           TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT    NOT NULL UNIQUE,
  expires_at TEXT    NOT NULL,
  created_at TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
`,
}

// migrate 按 user_version 顺序执行未应用的迁移。
func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	for v := version; v < len(migrations); v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration v%d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("set user_version: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	// 数据迁移：历史库中 pocs.file_path 存的是绝对路径（如
	// /Users/x/project/gobas/clone-templates/...），整体复制项目到其他机器后
	// 路径失效。此处统一改写为相对 baseDir 的相对路径（幂等，版本号不递增）：
	// 已经是相对路径的行走 RelPath 原样返回不更新，绝对但不属于本工作区的
	// 行同样跳过，AbsPath 读侧兼容两种形态。
	if err := s.relocatePOCPaths(); err != nil {
		return fmt.Errorf("relocate poc paths: %w", err)
	}
	return nil
}

func (s *Store) relocatePOCPaths() error {
	rows, err := s.db.Query(`SELECT id, file_path FROM pocs WHERE file_path != ''`)
	if err != nil {
		return err
	}
	type fix struct {
		id  int64
		rel string
	}
	var fixes []fix
	for rows.Next() {
		var id int64
		var fp string
		if err := rows.Scan(&id, &fp); err != nil {
			rows.Close()
			return err
		}
		rel := s.RelPath(fp)
		if rel != fp {
			fixes = append(fixes, fix{id: id, rel: rel})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, f := range fixes {
		if _, err := s.db.Exec(`UPDATE pocs SET file_path = ? WHERE id = ?`, f.rel, f.id); err != nil {
			return err
		}
	}
	return nil
}
