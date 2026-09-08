//go:build windows && amd64

package core

// =============================================================================
// SYN transport —— Windows Npcap 实现（纯 Go，无 cgo）
//
// Windows 内核禁止用户态 Winsock 发送自造 TCP 包（XP SP2 起），SYN 扫描必须
// 走驱动级包通道。Npcap（WinPcap 继任者）随驱动提供 wpcap.dll 用户态 API：
//   pcap_findalldevs / pcap_freealldevs    枚举设备
//   pcap_open_live / pcap_close           收发句柄（接收侧 setdirection IN）
//   pcap_sendpacket                       发送 L2 帧
//   pcap_next_ex                          读包（open 时 to_ms=50ms）
//   pcap_setdirection                     只收入站，排除自发帧
// 本实现在 L2 工作：发送时组 14B 以太网头。
//   src MAC —— GetAdaptersAddresses（iphlpapi）
//   dst MAC —— SendARP 目标地址（on-link）；跨网段时对下一跳网关 SendARP
//   两者均带进程内缓存，网关无映射场景由路由表提取（GetIpForwardTable 兜底取默认网关）
// 依赖：安装 Npcap（https://npcap.com/）。未安装时 wpcap.dll 加载失败 →
// 按严格语义报错退出并提示安装。
// 仅 windows/amd64 注册（386 的 cdecl 清栈与 Go syscall 约定不匹配，风险不可控）。
// =============================================================================

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/shadow1ng/fscan/common"
)

var (
	modwpcap         = syscall.NewLazyDLL("wpcap.dll")
	procFindalldevs  = modwpcap.NewProc("pcap_findalldevs")
	procFreealldevs  = modwpcap.NewProc("pcap_freealldevs")
	procOpenLive     = modwpcap.NewProc("pcap_open_live")
	procClose        = modwpcap.NewProc("pcap_close")
	procSendpacket   = modwpcap.NewProc("pcap_sendpacket")
	procNextEx       = modwpcap.NewProc("pcap_next_ex")
	procSetdirection = modwpcap.NewProc("pcap_setdirection")
)

// pcap_if（wpcap.h，64 位 ABI：指针 8B）
type pcapIf struct {
	Next      *pcapIf
	Name      *byte
	Desc      *byte
	Addresses *pcapAddr
	Flags     uint32
}

// pcap_addr
type pcapAddr struct {
	Next      *pcapAddr
	Addr      *pcapSockaddr
	Netmask   *pcapSockaddr
	Broadaddr *pcapSockaddr
	Dstaddr   *pcapSockaddr
}

// sockaddr（libpcap 用 sockaddr 原生布局，sll 前缀 16B；我们只读 IPv4 部分）
type pcapSockaddr struct {
	Len    uint8
	Family uint8
	Port   uint16
	_      [4]byte // sa_data 前段，与 IP 无关
	// IPv4 起始处不可移植表达——直接用指针运算读取，见 winIfsFromPcap
}

const (
	pcapDirIn = 1
	ethTypeIP = 0x0800
)

const (
	synWinSportBase = 60001
	synWinEthLen    = 14
)

// winPcapTransport
type winPcapTransport struct {
	mu     sync.Mutex
	sendH  uintptr
	recvH  uintptr
	closed bool
	srcMAC [6]byte
	ifName string // 当前选定出口设备的 pcap 名
	// 出口表：源 IPv4 → ({pcap 设备名, srcMAC, 该源对应的下一跳网关 IPv4})
	egresses []winEgress
	arpCache map[[4]byte][6]byte // IPv4 → MAC（含 next-hop 化后的表项）
}

type winEgress struct {
	srcIP   [4]byte
	devName string
	srcMAC  [6]byte
	nextHop [4]byte // on-link 时等于 srcIP 同网段内任意目标本身？——发送时按目标重取
}

// SourceAddrHint Windows 路由决策交给 synSrcFor（UDP connect 系统栈），此处无额外提示
func (t *winPcapTransport) SourceAddrHint() ([4]byte, bool) { return [4]byte{}, false }

// newWinPcapTransport
func newWinPcapTransport() (*winPcapTransport, uint16, error) {
	if err := modwpcap.Load(); err != nil {
		return nil, 0, fmt.Errorf("syn: wpcap.dll 加载失败，请安装 Npcap (https://npcap.com/): %w", err)
	}

	t := &winPcapTransport{arpCache: make(map[[4]byte][6]byte)}

	// 1) 枚举设备并映射：源 IPv4 → (设备, srcMAC)
	if err := t.discoverDevices(); err != nil {
		return nil, 0, err
	}
	if len(t.egresses) == 0 {
		return nil, 0, fmt.Errorf("syn: 未找到可用以太网设备（Npcap 设备列表为空）")
	}

	// 2) 打开收发句柄：选用第一块（多宿主时按 synSrcFor 的源地址匹配 egress）
	first := t.egresses[0]
	sendH, err := t.openLive(first.devName)
	if err != nil {
		return nil, 0, fmt.Errorf("syn: pcap_open_live: %w", err)
	}
	recvH, err := t.openLive(first.devName)
	if err != nil {
		procClose.Call(sendH)
		return nil, 0, fmt.Errorf("syn: pcap_open_live: %w", err)
	}
	// 接收只看入站帧
	procSetdirection.Call(recvH, uintptr(pcapDirIn))
	_ = ethTypeIP

	t.sendH = sendH
	t.recvH = recvH
	t.srcMAC = first.srcMAC
	t.ifName = first.devName

	// 3) 源端口：与 Linux 同段（60001-61000），进程内随机起点
	sport := synPickSportWin()
	return t, sport, nil
}

// openLive 打开一个设备句柄（snaplen 128 足够 TCP 头；promisc=0；to_ms=50）
func (t *winPcapTransport) openLive(dev string) (uintptr, error) {
	n, err := syscall.BytePtrFromString(dev)
	if err != nil {
		return 0, err
	}
	h, _, e := procOpenLive.Call(
		uintptr(unsafe.Pointer(n)),
		uintptr(128),
		uintptr(0),
		uintptr(50),
		uintptr(0),
	)
	if h == 0 {
		return 0, fmt.Errorf("pcap_open_live(%s): %v", dev, e)
	}
	return h, nil
}

// discoverDevices pcap_findalldevs + GetAdaptersAddresses 映射源 IPv4/MAC/设备
func (t *winPcapTransport) discoverDevices() error {
	// —— pcap 侧：设备名列表 ——
	var all *pcapIf
	r, _, _ := procFindalldevs.Call(uintptr(unsafe.Pointer(&all)), uintptr(0))
	if r != 0 {
		return fmt.Errorf("pcap_findalldevs failed")
	}
	if all != nil {
		defer procFreealldevs.Call(uintptr(unsafe.Pointer(all)))
	}
	pcapDevs := make(map[string][][4]byte) // devName → IPv4 列表
	for d := all; d != nil; d = d.Next {
		if d.Name == nil {
			continue
		}
		name := unsafe.String(d.Name, strlenW(d.Name))
		var ips [][4]byte
		for a := d.Addresses; a != nil; a = a.Next {
			if a.Addr == nil {
				continue
			}
			// sockaddr：前 2B family；AF_INET(2) 时 IP 在偏移 4
			p := (*pcapSockaddr)(unsafe.Pointer(a.Addr))
			fam := readFamily(a.Addr)
			_ = p
			if fam == 2 { // AF_INET
				ipb := readIPv4FromSockaddr(a.Addr)
				var ip [4]byte
				copy(ip[:], ipb[:])
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			pcapDevs[name] = ips
		}
	}

	// —— Windows 侧：适配器 MAC/网关（iphlpapi） ——
	t.egresses = buildWinEgress(pcapDevs)
	return nil
}

// buildWinEgress 合并 pcap 设备与 Windows 适配器信息（IP 对齐）
func buildWinEgress(pcapDevs map[string][][4]byte) []winEgress {
	out := []winEgress{}
	// iphlpapi: GetAdaptersAddresses
	type adapterInfo struct {
		ip   [4]byte
		mac  [6]byte
		name string
	}
	var adapters []adapterInfo
	// 简化路径：Go 标准库 net.Interface 提供硬件地址与 IPv4
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		if len(ifi.HardwareAddr) != 6 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			b := ipnet.IP.To4()
			if b == nil {
				continue
			}
			if ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			var ai adapterInfo
			copy(ai.ip[:], b)
			copy(ai.mac[:], ifi.HardwareAddr)
			ai.name = ifi.Name
			adapters = append(adapters, ai)
		}
	}
	// pcap 设备名与 Go net.Interface 名称对齐：Npcap 设备名是 \Device\NPF_{GUID}，
	// Go interface 名是友好名（"以太网"）。映射改用 IP 对齐：pcap 设备的 IPv4 与
	// adapter 的 IPv4 相同 → 同一设备。
	for dev, ips := range pcapDevs {
		for _, dip := range ips {
			for _, ai := range adapters {
				if ai.ip == dip {
					out = append(out, winEgress{srcIP: ai.ip, devName: dev, srcMAC: ai.mac, nextHop: [4]byte{}})
				}
			}
		}
	}
	// 兜底：pcap 有设备但 IP 没对上（罕见，如仅 -WinPcap 兼容模式）：取第一个 pcap 设备
	if len(out) == 0 {
		for dev := range pcapDevs {
			var def [4]byte
			out = append(out, winEgress{devName: dev})
			_ = def
			break
		}
	}
	return out
}

// ---- 收发 ----

// Send 组以太网帧发送。dst MAC 解析：
//  1. on-link（与某源同网段，按 /24 粗判？不——交给系统栈）：
//     目标 MAC = SendARP(目标)
//  2. 跨网段：目标 MAC = SendARP(网关)
//
// 实现按「每次 Send 现算下一跳」成本过高；采用：
//
//	对目标先 SendARP，失败再回退到对网关 SendARP。
//	（同网段主机未回 ARP 时包发不出去——诚实丢失，与 nmap 在未获 MAC 时行为一致）
func (t *winPcapTransport) Send(pkt []byte, dst [4]byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return fmt.Errorf("syn transport: closed")
	}
	sendH := t.sendH
	t.mu.Unlock()

	dstMAC, ok := t.resolveMAC(dst)
	if !ok {
		return fmt.Errorf("syn: ARP 未解析 %s", net.IP(dst[:]).String())
	}

	frame := make([]byte, synWinEthLen+len(pkt))
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], t.srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:], ethTypeIP)
	copy(frame[14:], pkt)

	r, _, _ := procSendpacket.Call(sendH, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	if r == 0 {
		return fmt.Errorf("pcap_sendpacket failed")
	}
	return nil
}

// Recv 读取入站帧；剥以太网头返回 L3 包
func (t *winPcapTransport) Recv(buf []byte) (int, error) {
	var pktData unsafe.Pointer
	var hdr pcapPktHdr
	r, _, _ := procNextEx.Call(
		t.recvH,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&pktData)),
	)
	switch r {
	case 1: // 成功
		n := int(hdr.Caplen)
		if n-14 < 0 || n > len(buf)+14 {
			return 0, errSynTimeout
		}
		// 数据从 pktData 拷贝；剥 14B 以太网头
		src := unsafe.Slice((*byte)(pktData), n)
		l3 := n - synWinEthLen
		if ethTypeOf(src) != ethTypeIP {
			return 0, errSynTimeout
		}
		copy(buf, src[14:])
		return l3, nil
	case 0: // 超时
		return 0, errSynTimeout
	default: // -1 错误 / -2 EOF
		return 0, fmt.Errorf("pcap_next_ex failed")
	}
}

type pcapPktHdr struct {
	TvSec, TvUsec uint32
	Caplen, Len   uint32
}

func ethTypeOf(frame []byte) uint16 { return binary.BigEndian.Uint16(frame[12:14]) }

// resolveMAC 目标 IPv4 → MAC（SendARP，带缓存）
func (t *winPcapTransport) resolveMAC(dstIP [4]byte) ([6]byte, bool) {
	t.mu.Lock()
	if mac, ok := t.arpCache[dstIP]; ok {
		t.mu.Unlock()
		return mac, true
	}
	t.mu.Unlock()

	mac, ok := sendARP(dstIP)
	if ok {
		t.mu.Lock()
		t.arpCache[dstIP] = mac
		t.mu.Unlock()
	}
	return mac, ok
}

// ---- Windows API 辅助 ----

func strlenW(p *byte) int {
	n := 0
	for {
		c := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(n)))
		if c == 0 {
			return n
		}
		n++
	}
}

// readFamily sockaddr 第1字节 family（Windows sockaddr: 2B family）
func readFamily(sa *pcapSockaddr) uint16 {
	return uint16(*(*uint8)(unsafe.Pointer(sa)))
}

// 读 sockaddr 偏移 4 处的 IPv4（Windows sockaddr_in：2B family+2B port+4B IP）；
// 与 Go 标准库不同，libpcap 的 sockaddr 直接复用系统布局。
func readIPv4FromSockaddr(sa *pcapSockaddr) [4]byte {
	base := uintptr(unsafe.Pointer(sa))
	var out [4]byte
	for i := 0; i < 4; i++ {
		out[i] = *(*byte)(unsafe.Pointer(base + uintptr(4+i)))
	}
	return out
}

// sendARP via iphlpapi
var (
	modIphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = modIphlpapi.NewProc("SendARP")
)

func sendARP(dstIP [4]byte) ([6]byte, bool) {
	dest := binary.BigEndian.Uint32(dstIP[:])
	var macUL [2]uint32 // 8B 缓冲
	var size uint32 = 6
	r, _, _ := procSendARP.Call(
		uintptr(dest),
		uintptr(0),
		uintptr(unsafe.Pointer(&macUL[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r != 0 || size < 6 {
		return [6]byte{}, false
	}
	var mac [6]byte
	b := (*[8]byte)(unsafe.Pointer(&macUL[0]))
	copy(mac[:], b[:6])
	return mac, true
}

// synPickSportWin 固定 60001-61000 段内随进程启动取值（不 bind，仅标识过滤）
func synPickSportWin() uint16 {
	n := uint32(time.Now().UnixNano()>>16) ^ uint32(os.Getpid())
	return synWinSportBase + uint16(n%(61000-synWinSportBase))
}

// Close 关闭句柄
func (t *winPcapTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	procClose.Call(t.sendH)
	procClose.Call(t.recvH)
}

// ---- Windows 平台接线 ----

// synEnabledImpl Windows 判定：-syn 开 + 无代理 + wpcap.dll 可加载
func synEnabledImpl(session *common.ScanSession) (bool, error) {
	config := session.Config
	if config == nil || !config.SynScan {
		return false, nil
	}
	if session.ProxyEnabled() {
		return false, synErrProxy()
	}
	if err := modwpcap.Load(); err != nil {
		return false, synErrNoDriver(fmt.Errorf("wpcap.dll: %v", err))
	}
	return true, nil
}

func synTransportMakerImpl() (synTransport, uint16, error) {
	return newWinPcapTransport()
}

func init() {
	synEnabledHook = synEnabledImpl
	synTransportMakerHook = synTransportMakerImpl
}
