package webproxy

// 「关闭必须秒回」回归：Stop 绝不能等正在拨号的请求退出来。
//
// 背景（号主报障）：点关闭偶尔卡好几秒。根因是 Stop 末尾的 wg.Wait()——
// 拨号中的请求要等到 DialTimeout（默认 3s，公司 VPN 劫持路由时更久）才退出，
// 在 Stop 里等它，用户看到的就是开关卡住、界面假死。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestStopDoesNotWaitForHangingDial(t *testing.T) {
	release := make(chan struct{})
	defer close(release) // 测试结束放行，避免协程永久泄漏

	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"example.com"},
		Resolve: func(host string) []string {
			return []string{"192.0.2.1"}
		},
		// 模拟「拨号卡死」：不响应 ctx、不回包，跟公司 VPN 劫持路由时一模一样
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-release
			return nil, errors.New("dial blocked")
		},
		DialTimeout: 30 * time.Second, // 故意超大：一旦 Stop 等它就必然超时失败
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}

	// 发一条 CONNECT，让 serve 进入拨号阻塞
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer c.Close()
	go func() {
		_, _ = fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		// 读一点，确保请求真的被 serve 处理
		_, _ = bufio.NewReader(c).ReadString('\n')
	}()

	time.Sleep(200 * time.Millisecond) // 给 serve 时间进入 Dial

	start := time.Now()
	if err := srv.Stop(); err != nil {
		t.Logf("Stop 返回错误（不致命）: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("Stop 耗时 %v，超过 500ms 上限：说明又在等拨号中的请求了", elapsed)
	}
	t.Logf("Stop 在 %v 内返回（拨号仍卡着，未阻塞）", elapsed)
}

// TestStopReleasesPortImmediately：Stop 返回后端口必须已经能重新监听，
// 否则用户「关掉又立刻打开」会撞端口占用。
func TestStopReleasesPortImmediately(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	srv := New(Options{
		Listen: "127.0.0.1:0",
		Hosts:  []string{"example.com"},
		Resolve: func(host string) []string {
			return []string{"192.0.2.1"}
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-release
			return nil, errors.New("dial blocked")
		},
		DialTimeout: 30 * time.Second,
	})
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer c.Close()
	_, _ = fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	time.Sleep(150 * time.Millisecond)

	_ = srv.Stop()

	// 立刻在同一个地址上重新监听：成功 = 端口确实已释放
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Stop 后端口 %s 仍被占用: %v", addr, err)
	}
	_ = ln.Close()
}
