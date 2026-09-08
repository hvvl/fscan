//go:build linux

package core

// =============================================================================
// SYN transport —— Linux raw socket 实现（需 CAP_NET_RAW）
//
// 发送：IPPROTO_RAW + IP_HDRINCL。注意：raw socket 未 connect 时 write() 不带
// msg_name 会被内核拒绝（EDESTADDRREQ），必须 sendto 显式携带目的地址——
// 线上的 IP 头仍取自包体（IP_HDRINCL），syscall 只提供路由目的。
// 接收：SOCK_RAW/IPPROTO_TCP。入站按 dport==sport 用户态过滤（processSeg）。
// =============================================================================

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	synLinuxSportMin = 60001
	synLinuxSportMax = 61000
)

// linuxRawTransport Linux raw 双 socket 实现
type linuxRawTransport struct {
	sendFD int
	recvFD int
}

// SourceAddrHint Linux raw 路径源地址由 IP_HDRINCL 包头决定（每 host 路由探测），
// 无平台级提示。
func (t *linuxRawTransport) SourceAddrHint() ([4]byte, bool) { return [4]byte{}, false }

// newLinuxRawTransport 创建 raw 通路；返回 (transport, sport)。
// 调用点已保证 CAP_NET_RAW（权限探测失败在最上层报错退出）。
func newLinuxRawTransport() (*linuxRawTransport, uint16, error) {
	sport, err := synPickSportLinux()
	if err != nil {
		return nil, 0, err
	}

	sendFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, 0, fmt.Errorf("syn: raw socket: %w", err)
	}
	if err := unix.SetsockoptInt(sendFD, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(sendFD)
		return nil, 0, fmt.Errorf("syn: IP_HDRINCL: %w", err)
	}

	recvFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		_ = unix.Close(sendFD)
		return nil, 0, fmt.Errorf("syn: recv socket: %w", err)
	}
	tv := unix.NsecToTimeval(int64(synRecvTimeout))
	_ = unix.SetsockoptTimeval(recvFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptInt(recvFD, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)

	return &linuxRawTransport{sendFD: sendFD, recvFD: recvFD}, sport, nil
}

// synPickSportLinux 60001-61000 中取可 bind 的源端口（临时 stream socket bind 测试；
// bind 仅为避开 ephemeral 冲突，raw 发包不依赖该 bind）
func synPickSportLinux() (uint16, error) {
	ephLo, ephHi := 32768, 60999
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 {
			if lo, e1 := strconv.Atoi(f[0]); e1 == nil {
				if hi, e2 := strconv.Atoi(f[1]); e2 == nil {
					ephLo, ephHi = lo, hi
				}
			}
		}
	}
	for p := synLinuxSportMin; p <= synLinuxSportMax; p++ {
		if p >= ephLo && p <= ephHi {
			continue
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return 0, err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet4{Port: p}); err == nil {
			_ = unix.Close(fd)
			return uint16(p), nil
		}
		_ = unix.Close(fd)
	}
	return 0, fmt.Errorf("syn: no bindable source port")
}

// Send 发送 L3 包（含 IP 头），sendto 显式目的地址（EDESTADDRREQ 教训）
func (t *linuxRawTransport) Send(pkt []byte, dst [4]byte) error {
	return unix.Sendto(t.sendFD, pkt, 0, &unix.SockaddrInet4{Addr: dst})
}

// Recv 读一个入站包；SO_RCVTIMEO 到期返回 errSynTimeout
func (t *linuxRawTransport) Recv(buf []byte) (int, error) {
	n, err := unix.Read(t.recvFD, buf)
	if err == nil {
		return n, nil
	}
	if err == unix.EAGAIN || err == unix.EINTR {
		return 0, errSynTimeout
	}
	return 0, err
}

// Close 释放
func (t *linuxRawTransport) Close() {
	_ = unix.Close(t.sendFD)
	_ = unix.Close(t.recvFD)
}

// synTransientClassifyLinux Linux 错误瞬态分类：
// EPERM 介于瞬态/致命之间：无 CAP_NET_RAW 时 sendto 会持续 EPERM，
// 若把它当瞬态会无限重试——致命处理。ENOBUFS/EAGAIN/EINTR 为瞬态。
func synTransientClassifyLinux(err error) bool {
	if err == unix.EAGAIN || err == unix.ENOBUFS || err == unix.EINTR {
		return true
	}
	if err == unix.EPERM {
		// sendto 的 EPERM 也可能是 icmp_filter 类限制，但 raw TCP 路径
		// 持续 EPERM 基本等于权限被拿走或 LSM 拦截：按致命处理，fscan 快速报错。
		return false
	}
	return false
}
