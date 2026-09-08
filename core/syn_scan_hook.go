package core

// =============================================================================
// SYN 半开扫描（-syn）跨平台接线与严格语义
//
// 严格模式语义（v2.2.3 起）：用户显式传 -syn 而运行环境不满足前置条件时，
// 不做任何静默回退——直接置 session.FatalErr 并中止扫描，CLI 报错退出(1)。
// 前置条件（全部由平台实现判定）：
//   - config.SynScan 开
//   - 未启用代理（用户态代理无法承载 raw 帧）
//   - 平台引擎可用（Linux: CAP_NET_RAW；Windows: Npcap wpcap.dll + amd64）
//   - 目标可解析为 IPv4（引擎只覆盖 IPv4；存在任何不可覆盖 host → 整体报错，不静默漏扫）
// =============================================================================

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/parsers"
)

// synEnabledHook enabled 判定（平台注入）：
// 返回 (ok, err)。ok=false 且 err!=nil 表示「用户要求 SYN 但环境不满足」→ 上层硬失败。
// ok=false 且 err=nil 表示平台选择不用 SYN（如 config.SynScan 未开启）→ 正常全连接。
var synEnabledHook func(session *common.ScanSession) (bool, error)

// synTransportMakerHook 平台 transport 构造（Linux raw / Windows Npcap）
var synTransportMakerHook func() (synTransport, uint16, error)

func synEnabled(session *common.ScanSession) (bool, error) {
	if synEnabledHook == nil {
		if session != nil && session.Config != nil && session.Config.SynScan {
			return false, synErrUnsupported(errors.New(i18n.GetText("syn_err_platform")))
		}
		return false, nil
	}
	return synEnabledHook(session)
}

// synErrUnsupported 统一包装：-syn 要求的运行环境不满足
type synUnsupportedError struct{ cause error }

func (e synUnsupportedError) Error() string {
	return i18n.GetText("syn_err_unsupported") + ": " + e.cause.Error()
}
func (e synUnsupportedError) Unwrap() error { return e.cause }

func synErrUnsupported(cause error) error {
	return synUnsupportedError{cause: cause}
}

// =============================================================================
// SYN 端口发现入口（平台无关）
// =============================================================================

// synPortDiscovery SYN 端口发现：返回开放 host:port（IPv4 canonical）。
// 严格语义引擎层不再自动回退；engine fatal 或构造失败都作为 error 上抛。
func synPortDiscoveryImpl(ctx context.Context, hosts []string, ports string, session *common.ScanSession, progressTotal bool) ([]string, error) {
	config := session.Config

	portList := parsers.ParsePort(ports)
	if len(portList) == 0 {
		return nil, fmt.Errorf("%v", i18n.Tr("invalid_port", ports))
	}

	excludePorts := parsers.ParsePort(config.Target.ExcludePorts)
	exclude := make(map[int]struct{}, len(excludePorts))
	for _, p := range excludePorts {
		exclude[p] = struct{}{}
	}

	// 严格语义：所有 host 必须可解析为 IPv4，否则整次 SYN 扫描报错
	eligible := make([]string, 0, len(hosts))
	var bad []string
	for _, h := range hosts {
		v, err := synCanonicalIPv4(h)
		if err != nil {
			bad = append(bad, h)
			continue
		}
		eligible = append(eligible, v)
	}
	if len(bad) > 0 {
		return nil, synErrUnsupported(fmt.Errorf("%v", i18n.Tr("syn_err_non_ipv4", len(bad), bad[0])))
	}
	if len(eligible) == 0 {
		return nil, synErrUnsupported(errors.New(i18n.GetText("syn_err_non_ipv4_empty")))
	}

	tr, sport, err := synTransportMaker()
	if err != nil {
		return nil, synErrUnsupported(err)
	}

	engine, err := newSynEngine(session, tr, sport)
	if err != nil {
		tr.Close()
		return nil, err
	}

	iter := NewSocketIterator(eligible, portList, exclude)
	total := iter.Total()
	if progressTotal && total > 0 && config.Output.ShowProgress {
		common.InitProgressBar(total, i18n.GetText("syn_progress_label"))
	}

	events := engine.Run(ctx, iter, synMaxInflight)

	if progressTotal && common.IsProgressActive() {
		common.FinishProgressBar()
	}
	engine.closeSynEngine()

	if err := engine.fatalErr(); err != nil {
		// 发包层致命：整次 SYN 失败（不可恢复）
		return nil, fmt.Errorf("syn: %w", err)
	}

	seen := make(map[string]struct{}, len(events))
	out := make([]string, 0, len(events))
	for _, ev := range events {
		host := net.IP(ev.ip[:]).String()
		addr := net.JoinHostPort(host, strconv.Itoa(ev.port))
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out, nil
}

// synCanonicalIPv4 host → IPv4 canonical（字面 IP 或 DNS）
func synCanonicalIPv4(h string) (string, error) {
	if ip := net.ParseIP(h); ip != nil {
		if b := ip.To4(); b != nil {
			return b.String(), nil
		}
		return "", fmt.Errorf("not IPv4: %s", h)
	}
	addr, err := common.DNSCache.ResolveIP(h)
	if err != nil || addr.IP == nil {
		return "", fmt.Errorf("unresolved: %s", h)
	}
	if b := addr.IP.To4(); b != nil {
		return b.String(), nil
	}
	return "", fmt.Errorf("not IPv4: %s", h)
}

// synPortDiscovery 平台无关调用入口（供 port_scan.go 调用；平台仅注入 transport maker）
func synPortDiscovery(ctx context.Context, hosts []string, ports string, session *common.ScanSession, progressTotal bool) ([]string, error) {
	return synPortDiscoveryImpl(ctx, hosts, ports, session, progressTotal)
}

// synTransportMaker 分发到平台构造（默认 nil → 不支持）
func synTransportMaker() (synTransport, uint16, error) {
	if synTransportMakerHook == nil {
		return nil, 0, errors.New(i18n.GetText("syn_err_platform"))
	}
	return synTransportMakerHook()
}

// ---- 平台共享错误构造（保持每个平台文件自包含）----

func synErrProxy() error {
	return synErrUnsupported(errors.New(i18n.GetText("syn_err_proxy")))
}

func synErrPermission(cause error) error {
	return synErrUnsupported(fmt.Errorf("%s (%v)", i18n.GetText("syn_err_no_cap"), cause))
}

func synErrNoDriver(cause error) error {
	return synErrUnsupported(fmt.Errorf("%s (%v)", i18n.GetText("syn_err_no_npcap"), cause))
}

// abortFromCtx 通知 RunScan 注入的 Abort 回调（若有）
func abortFromCtx(ctx context.Context) {
	if c, ok := ctx.Value(abortKey{}).(func()); ok {
		c()
	}
}
