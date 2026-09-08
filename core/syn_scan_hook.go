package core

import (
	"context"

	"github.com/shadow1ng/fscan/common"
)

// SYN 半开扫描的跨平台接线层。
// 所有平台侧实现（引擎本体、enabled 判定、端口发现入口）由 Linux 实现注入；
// 非 Linux 平台两个 hook 均为 nil → 永远走全连接，行为与上游一致。

// synEnabledHook enabled 判定注入点（Linux/syn_scan_linux.go 中赋值）
var synEnabledHook func(session *common.ScanSession) bool

// synDiscoveryHook 端口发现引擎入口注入点（Linux/syn_scan_linux.go 中赋值）。
// 返回 nil 表示引擎不可用/请求失败，调用方应整体回退全连接。
var synDiscoveryHook func(ctx context.Context, hosts []string, ports string, session *common.ScanSession, progressTotal bool) []string

// synEnabled 本次会话是否启用 SYN 半开扫描
func synEnabled(session *common.ScanSession) bool {
	if synEnabledHook == nil {
		return false
	}
	return synEnabledHook(session)
}

// synPortDiscovery 平台端口发现入口（无实现时恒为 nil，调用方判定后回退）
func synPortDiscovery(ctx context.Context, hosts []string, ports string, session *common.ScanSession, progressTotal bool) []string {
	if synDiscoveryHook == nil {
		return nil
	}
	return synDiscoveryHook(ctx, hosts, ports, session, progressTotal)
}
