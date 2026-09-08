package core

// =============================================================================
// SYN 半开扫描 —— 平台无关引擎（-syn）
//
// 端口发现阶段以自建 IPv4/TCP SYN 探测包扫描（不完成三次握手）：
//   - SYN|ACK → 端口开放（以 ACK-1 回查 ISN cookie 确认归属，五元组+cookie 双筛）。
//     发包侧无需回 ACK：内核因无监听 socket 自动回 RST —— closed 端口全程无完整连接
//   - RST      → 端口关闭
//   - 限时重传后无响应 → filtered
// 发现的开放端口再走一次全连接进入既有服务识别链路（等价 nmap -sS + -sV）。
//
// ISN = fnv32(dstIP|dstPort|salt)|1，SYN|ACK 的 ACK-1 即归属凭证；
// 源地址按 host 路由探测选取（UDP connect，不发数据包），多宿主正确。
//
// 平台相关部分收敛为 synTransport 接口：
//   Linux   → 直接 raw socket（core/syn_transport_linux.go，需 CAP_NET_RAW）
//   Windows → Npcap/wpcap.dll 包注入+捕获（core/syn_transport_windows.go）
// 引擎本体（cookie、重传、sweep、多路收包）全部平台无关，位于本文件。
// =============================================================================

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
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

// protoTCP 常量（平台无关层不得 import x/sys/unix，Windows 文件同样引用）
const protoTCP = 6

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

// synBuildPkt 40B SYN 探测包（平台无关：两平台的包格式一致）
func synBuildPkt(src, dst [4]byte, sport, dport uint16, seq uint32, ipID uint16) [synProbeLen]byte {
	var pkt [synProbeLen]byte
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:], synProbeLen)
	binary.BigEndian.PutUint16(pkt[4:], ipID)
	binary.BigEndian.PutUint16(pkt[6:], 0x4000)
	pkt[8] = 64
	pkt[9] = protoTCP
	copy(pkt[12:], src[:])
	copy(pkt[16:], dst[:])

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 0x50
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:], 1024)

	var full [32]byte
	copy(full[0:], src[:])
	copy(full[4:], dst[:])
	full[8] = 0
	full[9] = protoTCP
	binary.BigEndian.PutUint16(full[10:], 20)
	copy(full[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], synChecksum(full[:]))
	binary.BigEndian.PutUint16(pkt[10:], synChecksum(pkt[:]))
	return pkt
}

// synSrcFor 路由选源地址（平台无关：UDP connect 不发数据包）
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

// =============================================================================
// transport 接口
// =============================================================================

// synTransport 平台包通路。实现必须保证：
//   - Send(pkt, dst) 发出发送缓冲区中的完整 L3 包（含 IP 头）
//   - Recv(buf) 读取一个入站 IPv4/TCP 包到 buf，返回长度；
//     无数据时返回 errTimeout（可安全重读）；致命错误返回其他错误
//   - Close 释放资源；实现自身的 transient 错误（EAGAIN/ENOBUFS 等）由引擎
//     侧统一按瞬态处理，见 synIsTransientErr
type synTransport interface {
	Send(pkt []byte, dst [4]byte) error
	Recv(buf []byte) (int, error)
	Close()
	// SourceAddrHint 若实现可提供更优的本地源地址选择（可返回空）
	SourceAddrHint() ([4]byte, bool)
}

// errSynTimeout transport 层统一“读超时”
var errSynTimeout = fmt.Errorf("syn transport: read timeout")

// synIsTransientErr 平台实现错误分类：瞬态可重试
var synTransientClassify func(err error) bool

// synIsTransientErr 引擎侧统一瞬态判定（nil 分类器时保守判 false）
func synIsTransientErr(err error) bool {
	if synTransientClassify == nil {
		return false
	}
	return synTransientClassify(err)
}

// =============================================================================
// 引擎主体
// =============================================================================

// synProbeRec 在途探测
type synProbeRec struct {
	src      [4]byte
	seq      uint32
	deadline int64 // unixnano
	sends    uint8
	sentAt   int64 // unixnano
}

// synOpenEvent 开放端口事件（发现序）
type synOpenEvent struct {
	ip   [4]byte
	port int
	rtt  time.Duration
}

type synEngine struct {
	session  *common.ScanSession
	tr       synTransport
	sport    uint16
	salt     uint32
	retryTO  time.Duration
	maxSends uint8

	mu       sync.Mutex
	inflight map[uint64]synProbeRec

	openCount atomic.Int64
	filtered  atomic.Int64
	closed    atomic.Int64

	// fatal: 发包层出现不可恢复错误（全体探测必失败），置位后整条
	// 流水线停止发送。lastSendErr 保留原因。
	fatal         atomic.Bool
	lastSendErrMu sync.Mutex
	lastSendErr   error

	events chan synOpenEvent
	// evSpill: events 满时接收侧暂存，避免 receiver goroutine 阻塞
	// 导致后续 SYN|ACK 无人处理（大规模扫描下假 filtered）。
	evSpill []synOpenEvent

	// recvDone: 扫描收尾时通知 recvLoop 退出（ctx 不随单次扫描结束而取消，
	// 若只依赖 ctx.Err()，wg.Wait() 将永远阻塞 → 全扫描挂死）
	recvDone chan struct{}
}

// newSynEngine sport 由 transport 的 SourceAddrHint/平台选源口逻辑给出；
// 简化：引擎不 bind 源端口（raw 路径无需 bind），源端口选择属于平台实现（见各 transport 文件，
// linux 固定 60001-61000 bind 以便 dport 过滤，windows 由 wpcap 侧过滤不需要 bind）。
func newSynEngine(session *common.ScanSession, tr synTransport, sport uint16) (*synEngine, error) {
	return &synEngine{
		sport:    sport,
		session:  session,
		tr:       tr,
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
	e.tr.Close()
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
		n, err := e.tr.Recv(buf)
		if err != nil {
			if err == errSynTimeout || synIsTransientErr(err) {
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
	if seg[0]>>4 != 4 || seg[9] != protoTCP {
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
	case flags&0x12 == 0x12: // SYN|ACK
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
	case flags&0x04 != 0: // RST
		e.finishClosed(key)
	}
}

// ---- sender + sweeper ----

// synSendOne 发包。返回 false=瞬态失败（待重试），true=已发出或 fatal 短路。
func (e *synEngine) synSendOne(key uint64, rec synProbeRec, now time.Time) bool {
	ipInt := uint32(key >> 32)
	port := uint16(key)
	var dst [4]byte
	binary.BigEndian.PutUint32(dst[:], ipInt)
	pkt := synBuildPkt(rec.src, dst, e.sport, port, rec.seq, uint16(key))
	if err := e.tr.Send(pkt[:], dst); err != nil {
		if synIsTransientErr(err) {
			return false // 瞬态：不登记/回滚，稍后重试
		}
		// 非瞬态：继续发必然全军覆没，置 fatal 止损位
		e.markFatal(err)
		return true
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
			return // 发包层整体失效，Run 做 fatal 决策
		}
		if time.Since(lastSweep) >= synSweepInterval {
			e.sweep()
			lastSweep = time.Now()
			if e.fatal.Load() {
				return
			}
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
				if e.fatal.Load() {
					return
				}
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
				continue // 无路由：host 全部端口只能标 filtered？——不影响引擎层
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

		// 先登记后发送：低 RTT 环境响应可能在 Send 返回前就进 receive 队列，
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
		if rec.sends < uint8(e.maxSends) {
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
drain:
	for e.inflightLen() > 0 {
		if ctx.Err() != nil || time.Now().After(ph) {
			break
		}
		e.sweep()
		select {
		case <-ctx.Done():
			break drain
		case <-time.After(30 * time.Millisecond):
		}
	}
	// 收尾：未决探测一律按 filtered 记账（进度条结束）；fatal 决策交给上层。
	if err := e.fatalErr(); err != nil {
		report := fmt.Sprintf("syn: send aborted: %v", err)
		if e.session != nil {
			e.session.LogError(report)
		}
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
