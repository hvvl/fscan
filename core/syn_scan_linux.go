//go:build linux

package core

// =============================================================================
// SYN 平台接线 —— Linux
//
// 前置判定（严格语义）：config.SynScan 开 + 无代理 + raw socket 可用。
// 任一不满足且用户显式开启 -syn → 返回错误（上层报错退出，不回退）。
// =============================================================================

import (
	"github.com/shadow1ng/fscan/common"

	"golang.org/x/sys/unix"
)

// synEnabledImpl Linux 判定
func synEnabledImpl(session *common.ScanSession) (bool, error) {
	config := session.Config
	if config == nil || !config.SynScan {
		return false, nil // 用户没开 -syn：正常全连接
	}
	// 用户显式开启；从此处开始的不满足都是「环境不满足」→ 报错
	if session.ProxyEnabled() {
		return false, synErrProxy()
	}
	// raw socket 权限探测
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return false, synErrPermission(err)
	}
	_ = unix.Close(fd)
	return true, nil
}

// synTransportMakerImpl Linux raw transport
func synTransportMakerImpl() (synTransport, uint16, error) {
	return newLinuxRawTransport()
}

func init() {
	synEnabledHook = synEnabledImpl
	synTransportMakerHook = synTransportMakerImpl
	synTransientClassify = synTransientClassifyLinux
}
