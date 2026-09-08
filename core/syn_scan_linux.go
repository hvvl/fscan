//go:build linux

package core

// =============================================================================
// SYN 半开扫描（-syn，仅 Linux，需 CAP_NET_RAW）
//
// 工作方式：
//   端口发现阶段以 raw socket 构造 TCP SYN 探测（IPPROTO_RAW + IP_HDRINCL）：
//     - SYN|ACK → 端口开放（以 ACK-1 回查 ISN cookie 确认归属，五元组+cookie 双筛）。
//       内核因无监听 socket 自动回 RST，不完成三次握手 —— closed 端口全程无完整连接
//     - RST      → 端口关闭
//     - 限时重传后无响应 → filtered
//   发现的开放端口再走一次全连接进入既有服务识别链路（等价 nmap -sS + -sV）。
//
//   ISN = fnv32(dstIP|dstPort|salt)|1，SYN|ACK 的 ACK-1 即归属凭证；
//   源地址按 host 路由探测选取（UDP connect，不发数据包），多宿主正确；
//   固定源端口（60001-61000 区间实测可 bind 且避开 ephemeral），按 dport 过滤回包。
//   与代理互斥：配置了 SOCKS/HTTP 代理时由上层直接走全连接（用户态代理无法转发 raw 包）。
// =============================================================================

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
	"github.com/shadow1ng/fscan/common/i18n"
	"github.com/shadow1ng/fscan/common/parsers"
	"golang.org/x/sys/unix"
)

const (
	synProbeLen      = 40 // 20B IP + 20B TCP
	synMaxInflight   = 8192
	synRecvTimeout   = 50 * time.Millisecond
	synSweepInterval = 200 * time.Millisecond
	synChanCap       = 1024
	synDrainTime     = 3*800*time.Millisecond + 500*time.Millisecond
	synDefaultRetry  = 800 * time.Millisecond
	synDefaultSend   = 3 // 首发+2 重传
)

// synOpenEvent 开放端口事件（发现序）
type synOpenEvent struct {
	ip   [4]byte
	port int
	rtt  time.Duration
}

// synProbeRec 在途探测
type synProbeRec struct {
	src      [4]byte
	seq      uint32
	deadline int64 // unixnano
	sends    uint8
	sentAt   int64 // unixnano
}

type synEngine struct {
	session *common.ScanSession
	sendFD  int
	recvFD  int
	sport   uint16
	salt    uint32
	retryTO time.Duration
	maxSends uint8

	mu       sync.Mutex
	inflight map[uint64]synProbeRec

	openCount atomic.Int64
	filtered  atomic.Int64
	closed    atomic.Int64

	// fatal: 发包层出现不可恢复错误（全体探测必失败），置位后整条
	// 流水线应停止发送并让上层回退全连接。lastSendErr 保留原因。
	fatal      atomic.Bool
	lastSendErrMu sync.Mutex
	lastSendErr error

	events chan synOpenEvent
	// evSpill: events 满时接收侧暂存，避免 receiver goroutine 阻塞
	// 导致后续 SYN|ACK 无人处理（大规模扫描下假 filtered）。
	evSpill []synOpenEvent

	// recvDone: 扫描收尾时通知 recvLoop 退出（ctx 不随单次扫描结束而取消，
	// 若只依赖 ctx.Err()，wg.Wait() 将永远阻塞 → 全扫描挂死）
	recvDone chan struct{}
}

// synProbeKey ip<<32|port
func synProbeKey(ip [4]byte, port uint16) uint64 {
	return uint64(binary.BigEndian.Uint32(ip[:]))<<32 | uint64(port)
}

// synISN fnv32(ip|port|salt)|1
func synISN(ip [4]byte, port uint16, salt uint32) uint32 {
	h := fnv.New32a()
	var b [10]byte
	copy(b[:4], ip[:])
	binary.BigEndian.PutUint16(b[4:], port)
	binary.LittleEndian.PutUint32(b[6:], salt)
	_, _ = h.Write(b[:])
	v := h.Sum32() | 1
	if v == 0xFFFFFFFF {
		v = 0xFFFFFFFE
	}
	return v
}

// synChecksum Internet checksum
func synChecksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	i := 0
	for ; i+1 < n; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// synBuildPkt 40B SYN 包
func synBuildPkt(src, dst [4]byte, sport, dport uint16, seq uint32, ipID uint16) [synProbeLen]byte {
	var pkt [synProbeLen]byte
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], synProbeLen)
	binary.BigEndian.PutUint16(pkt[4:], ipID)
	binary.BigEndian.PutUint16(pkt[6:], 0x4000)
	pkt[8] = 64
	pkt[9] = unix.IPPROTO_TCP
	copy(pkt[12:], src[:])
	copy(pkt[16:], dst[:])

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 0x50
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:], 1024)

	var full [32]byte
	copy(full[0:], src[:])
	copy(full[4:], dst[:])
	full[8] = 0
	full[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(full[10:], 20)
	copy(full[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], synChecksum(full[:]))
	binary.BigEndian.PutUint16(pkt[10:], synChecksum(pkt[:]))
	return pkt
}

// synPickSport 固定源端口：60001-61000，避开 ephemeral，实测 bind
func synPickSport() (uint16, error) {
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
	for p := 60001; p <= 61000; p++ {
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

// synSrcFor 路由选源地址
func synSrcFor(host string) ([4]byte, bool) {
	c, err := net.DialTimeout("udp", net.JoinHostPort(host, "9"), 500*time.Millisecond)
	if err != nil {
		return [4]byte{}, false
	}
	defer func() { _ = c.Close() }()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
		if b4 := ua.IP.To4(); b4 != nil {
			var out [4]byte
			copy(out[:], b4)
			return out, true
		}
	}
	return [4]byte{}, false
}

func newSynEngine(session *common.ScanSession) (*synEngine, error) {
	sport, err := synPickSport()
	if err != nil {
		return nil, err
	}
	sendFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("syn: raw socket: %w", err)
	}
	if err := unix.SetsockoptInt(sendFD, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(sendFD)
		return nil, fmt.Errorf("syn: IP_HDRINCL: %w", err)
	}
	recvFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		_ = unix.Close(sendFD)
		return nil, fmt.Errorf("syn: recv socket: %w", err)
	}
	tv := unix.NsecToTimeval(int64(synRecvTimeout))
	_ = unix.SetsockoptTimeval(recvFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptInt(recvFD, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)

	return &synEngine{
		session:  session,
		sendFD:   sendFD,
		recvFD:   recvFD,
		sport:    sport,
		salt:     uint32(time.Now().UnixNano()) ^ (uint32(os.Getpid()) << 16),
		retryTO:  synDefaultRetry,
		maxSends: synDefaultSend,
		inflight: make(map[uint64]synProbeRec, 8192),
		events:   make(chan synOpenEvent, synChanCap),
		recvDone: make(chan struct{}),
	}, nil
}

// markFatal 记录致命中止原因并置位（幂等）
func (e *synEngine) markFatal(err error) {
	if e.fatal.Swap(true) {
		return // 首个 fatal 原因保留
	}
	e.lastSendErrMu.Lock()
	e.lastSendErr = err
	e.lastSendErrMu.Unlock()
}

func (e *synEngine) fatalErr() error {
	e.lastSendErrMu.Lock()
	defer e.lastSendErrMu.Unlock()
	return e.lastSendErr
}

func (e *synEngine) closeSynEngine() {
	_ = unix.Close(e.sendFD)
	_ = unix.Close(e.recvFD)
}

func (e *synEngine) inflightLen() int {
	e.mu.Lock()
	n := len(e.inflight)
	e.mu.Unlock()
	return n
}

// ---- 终结 ----

func (e *synEngine) finishOpen(key uint64, ip [4]byte, port uint16, rtt time.Duration) bool {
	e.mu.Lock()
	if _, ok := e.inflight[key]; !ok {
		e.mu.Unlock()
		return false
	}
	delete(e.inflight, key)
	e.mu.Unlock()
	e.openCount.Add(1)
	if common.IsProgressActive() {
		common.UpdateProgressBar(1)
	}
	ev := synOpenEvent{ip: ip, port: int(port), rtt: rtt}
	select {
	case e.events <- ev:
	default:
		// chan 满：暂存，由 Run 收尾时合并，receiver 不被反压阻塞
		e.mu.Lock()
		e.evSpill = append(e.evSpill, ev)
		e.mu.Unlock()
	}
	return true
}

func (e *synEngine) finishClosed(key uint64) {
	e.mu.Lock()
	if _, ok := e.inflight[key]; !ok {
		e.mu.Unlock()
		return
	}
	delete(e.inflight, key)
	e.mu.Unlock()
	e.closed.Add(1)
	if common.IsProgressActive() {
		common.UpdateProgressBar(1)
	}
}

func (e *synEngine) finishFiltered() {
	e.filtered.Add(1)
	if common.IsProgressActive() {
		common.UpdateProgressBar(1)
	}
}

// ---- receiver ----

func (e *synEngine) recvLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 2048)
	for {
		select {
		case <-e.recvDone:
			return
		default:
		}
		if ctx.Err() != nil {
			return
		}
		n, err := unix.Read(e.recvFD, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return
		}
		if n < 40 {
			continue
		}
		e.processSeg(buf[:n])
	}
}

func (e *synEngine) processSeg(seg []byte) {
	if seg[0]>>4 != 4 || seg[9] != unix.IPPROTO_TCP {
		return
	}
	ihl := int(seg[0]&0x0F) * 4
	if ihl < 20 || len(seg) < ihl+20 {
		return
	}
	tcp := seg[ihl:]
	if binary.BigEndian.Uint16(tcp[2:4]) != e.sport {
		return
	}
	var srcIP [4]byte
	copy(srcIP[:], seg[12:16])
	rport := binary.BigEndian.Uint16(tcp[0:2])
	key := synProbeKey(srcIP, rport)

	flags := tcp[13]
	switch {
	case flags&0x12 == 0x12:
		ack := binary.BigEndian.Uint32(tcp[8:12])
		if ack-1 != synISN(srcIP, rport, e.salt) {
			return
		}
		e.mu.Lock()
		rec, ok := e.inflight[key]
		var rtt time.Duration
		if ok {
			rtt = time.Since(time.Unix(0, rec.sentAt))
		}
		e.mu.Unlock()
		if !ok {
			return
		}
		_ = rec
		e.finishOpen(key, srcIP, rport, rtt)
	case flags&0x04 != 0:
		e.finishClosed(key)
	}
}

// ---- sender + sweeper ----

// synSendOne 发包。返回 false=瞬态失败（ENOBUFS 等），true=已发出或致命放弃。
// 注意：raw socket 未 connect 时 write() 不带目的地址会返回 EDESTADDRREQ，
// 必须用 sendto 经 msg_name 提供路由目的（线上的 IP 头仍取自包体，IP_HDRINCL）。
func (e *synEngine) synSendOne(key uint64, rec synProbeRec, now time.Time) bool {
	ipInt := uint32(key >> 32)
	port := uint16(key)
	var dst [4]byte
	binary.BigEndian.PutUint32(dst[:], ipInt)
	pkt := synBuildPkt(rec.src, dst, e.sport, port, rec.seq, uint16(key))
	if err := unix.Sendto(e.sendFD, pkt[:], 0, &unix.SockaddrInet4{Addr: dst}); err != nil {
		if err == unix.EAGAIN || err == unix.ENOBUFS || err == unix.EINTR || err == unix.EPERM {
			return false // 瞬态：不登记/回滚，稍后重试
		}
		// 非瞬态（EDESTADDRREQ/ENETUNREACH/EINVAL 等）：
		// 继续发必然全军覆没，置 fatal 止损位，上层整体回退全连接
		e.markFatal(err)
		return true // 不再重试该包：fatal 已短路整条流水线
	}
	return true
}

func (e *synEngine) runSender(ctx context.Context, iter *SocketIterator, srcCache map[string][4]byte, inflightCap int) {
	lastSweep := time.Now()

	for {
		if ctx.Err() != nil {
			return
		}
		if e.fatal.Load() {
			return // 发包层整体失效，Run 会做回退决策
		}
		if time.Since(lastSweep) >= synSweepInterval {
			e.sweep()
			lastSweep = time.Now()
		}
		if e.inflightLen() >= inflightCap {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Millisecond):
			}
			continue
		}

		host, port, ok := iter.Next()
		if !ok {
			if e.inflightLen() == 0 {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(synSweepInterval):
				e.sweep()
				lastSweep = time.Now()
			}
			continue
		}
		if port < 1 || port > 65535 {
			continue
		}

		var dst [4]byte
		if ip := net.ParseIP(host); ip != nil {
			b := ip.To4()
			if b == nil {
				continue
			}
			copy(dst[:], b)
		} else if addr, err := common.DNSCache.ResolveIP(host); err == nil {
			b := addr.IP.To4()
			if b == nil {
				continue
			}
			copy(dst[:], b)
		} else {
			continue
		}

		src, ok2 := srcCache[host]
		if !ok2 {
			s, ok3 := synSrcFor(host)
			if !ok3 {
				continue // 交上层 connect 兜底
			}
			src = s
			srcCache[host] = src
		}

		key := synProbeKey(dst, uint16(port))
		e.mu.Lock()
		if _, dup := e.inflight[key]; dup {
			e.mu.Unlock()
			continue
		}
		e.mu.Unlock()

		seq := synISN(dst, uint16(port), e.salt)
		now := time.Now()
		rec := synProbeRec{src: src, seq: seq, deadline: now.Add(e.retryTO).UnixNano(), sends: 1, sentAt: now.UnixNano()}

		// 先登记后发送：lo/低RTT 环境响应可能在 sendto 返回前就进 receive 队列，
		// 若此时 map 尚无 key，receiver 会把正当响应当噪声丢弃。
		// 先插入再发包，窗口期内的“响应”受 ISN cookie 约束不会误匹配。
		e.mu.Lock()
		if _, dup := e.inflight[key]; dup {
			e.mu.Unlock()
			continue
		}
		e.inflight[key] = rec
		e.mu.Unlock()

		if !e.synSendOne(key, rec, now) {
			// 瞬态失败：回滚登记，待重试
			e.mu.Lock()
			if cur, ok := e.inflight[key]; ok && cur.sends == rec.sends && cur.deadline == rec.deadline {
				delete(e.inflight, key)
			}
			e.mu.Unlock()
			continue
		}
	}
}

// sweep 超时重传 / filtered 终结
func (e *synEngine) sweep() {
	nowNS := time.Now().UnixNano()
	now := time.Now()

	type toResend struct {
		key uint64
		rec synProbeRec
	}
	var resends []toResend
	var drops []uint64

	e.mu.Lock()
	for k, rec := range e.inflight {
		if nowNS < rec.deadline {
			continue
		}
		if rec.sends < e.maxSends {
			rec.sends++
			rec.deadline = nowNS + int64(e.retryTO)
			e.inflight[k] = rec
			resends = append(resends, toResend{k, rec})
		} else {
			delete(e.inflight, k)
			drops = append(drops, k)
		}
	}
	e.mu.Unlock()

	for _, r := range resends {
		if e.fatal.Load() {
			break
		}
		if !e.synSendOne(r.key, r.rec, now) {
			// 瞬态失败：回滚，deadline 保持近期，尽快重试
			e.mu.Lock()
			if rec, ok := e.inflight[r.key]; ok {
				if rec.sends > 0 {
					rec.sends--
				}
				rec.deadline = now.Add(e.retryTO).UnixNano()
				e.inflight[r.key] = rec
			}
			e.mu.Unlock()
		}
	}
	for range drops {
		e.finishFiltered()
	}
}

// ---- Run ----

func (e *synEngine) Run(ctx context.Context, iter *SocketIterator, inflightCap int) []synOpenEvent {
	srcCache := make(map[string][4]byte, 256)

	var wg sync.WaitGroup
	wg.Add(1)
	go e.recvLoop(ctx, &wg)

	e.runSender(ctx, iter, srcCache, inflightCap)

	ph := time.Now().Add(synDrainTime)
	for e.inflightLen() > 0 {
		if ctx.Err() != nil || time.Now().After(ph) {
			break
		}
		e.sweep()
		select {
		case <-ctx.Done():
			break
		case <-time.After(30 * time.Millisecond):
		}
	}
	// 发包层致命错误：当前 inflight 全部视为 filtered 结束进度条，整体交上层回退
	if err := e.fatalErr(); err != nil {
		report := fmt.Sprintf("syn: send aborted: %v", err)
		if e.session != nil {
			e.session.LogError(report)
		}
		remaining := e.inflightLen()
		for i := 0; i < remaining; i++ {
			e.finishFiltered()
		}
		e.mu.Lock()
		for k := range e.inflight {
			delete(e.inflight, k)
		}
		e.mu.Unlock()
	}

	remaining := e.inflightLen()
	for i := 0; i < remaining; i++ {
		e.finishFiltered()
	}
	e.mu.Lock()
	for k := range e.inflight {
		delete(e.inflight, k)
	}
	e.mu.Unlock()

	close(e.recvDone) // recvLoop 出口；否则 wg.Wait 永久阻塞（ctx 无人取消）
	wg.Wait()
	close(e.events)
	// 先排干 chan，再合并溢出暂存，保持发现顺序
	out := make([]synOpenEvent, 0, len(e.events))
	for ev := range e.events {
		out = append(out, ev)
	}
	e.mu.Lock()
	out = append(out, e.evSpill...)
	e.evSpill = nil
	e.mu.Unlock()
	return out
}

// =============================================================================
// EnhancedPortScan 的 SYN 分支
// =============================================================================

// synPortDiscoveryImpl SYN 模式入口：返回开放 host:port 列表（IPv4 canonical）
// 只做端口发现；库存结果（saveOpenPort）与服务识别由端口扫描主函数的 SYN 分支处理。
func synPortDiscoveryImpl(ctx context.Context, hosts []string, ports string, session *common.ScanSession, progressTotal bool) []string {
	config := session.Config

	portList := parsers.ParsePort(ports)
	if len(portList) == 0 {
		session.LogError(i18n.Tr("invalid_port", ports))
		return nil
	}

	excludePorts := parsers.ParsePort(config.Target.ExcludePorts)
	exclude := make(map[int]struct{}, len(excludePorts))
	for _, p := range excludePorts {
		exclude[p] = struct{}{}
	}

	eligible := synEligibleHosts(hosts)
	if len(eligible) == 0 {
		return nil
	}

	engine, err := newSynEngine(session)
	if err != nil {
		session.LogInfo(i18n.Tr("syn_fallback_connect", err))
		return nil // 调用方走回退
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

	// 发包层致命错误（raw 通路整体失效）：返回 nil，让 synPortScan 整体回退全连接。
	// 注意不能用空列表——空列表语义是「扫完且确认无开放端口」。
	if engine.fatal.Load() {
		return nil
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
	return out
}

// synEligibleHosts SYN 层可覆盖的 host → IPv4 canonical string
func synEligibleHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		switch {
		case net.ParseIP(h) != nil:
			if b := net.ParseIP(h).To4(); b != nil {
				out = append(out, b.String())
			}
		default:
			if addr, err := common.DNSCache.ResolveIP(h); err == nil {
				if b := addr.IP.To4(); b != nil {
					out = append(out, b.String())
				}
			}
		}
	}
	return out
}


// =============================================================================
// 平台接线（Linux）
// =============================================================================

// synEnabledImpl Linux 下 -syn 的有效性判定：
// 配置开关 + 无代理（用户态代理无法承载 raw 包）+ CAP_NET_RAW。
func synEnabledImpl(session *common.ScanSession) bool {
	config := session.Config
	if config == nil || !config.SynScan {
		return false
	}
	// 代理模式：SYN 无法穿透用户态代理，直接保持全连接
	if session.ProxyEnabled() {
		return false
	}
	// 权限探测：能否打开 raw socket
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		session.LogInfo(i18n.GetText("syn_no_raw"))
		return false
	}
	_ = unix.Close(fd)
	return true
}

func init() {
	synEnabledHook = synEnabledImpl
	synDiscoveryHook = synPortDiscoveryImpl
}
