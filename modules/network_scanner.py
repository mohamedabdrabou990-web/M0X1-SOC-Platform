
import argparse
import asyncio
import ipaddress
import json
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ----------------------------------------------------------------------------
# Common ports (top ~100) - used with --top-ports instead of scanning all 65535
# ----------------------------------------------------------------------------
TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138,
    139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 514, 515, 520, 521,
    540, 546, 547, 587, 631, 636, 660, 691, 860, 873, 902, 989, 990, 993, 995,
    1080, 1194, 1433, 1434, 1521, 1723, 1741, 1755, 1812, 1813, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 27017, 27018, 3000,
    3268, 3269, 3306, 3389, 3690, 4433, 4444, 4500, 5000, 5432, 5601, 5900,
    5985, 5986, 6379, 6443, 6660, 6667, 7001, 7077, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999, 11211, 27015,
    50000,
]

COMMON_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle-DB", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis", 6443: "K8s-API",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""


@dataclass
class HostResult:
    ip: str
    alive: bool = False
    hostname: str = ""
    response_time_ms: Optional[float] = None
    open_ports: List[PortResult] = field(default_factory=list)


# ----------------------------------------------------------------------------
# 1) Host Discovery
# ----------------------------------------------------------------------------
async def is_host_alive(ip: str, timeout: float) -> Optional[float]:
    """
    Tries a fast TCP connection on a few common ports as a discovery
    method (faster and more reliable than ICMP ping, which requires
    root privileges on Linux and is often blocked on networks).
    Returns response time in ms if the host is alive, or None otherwise.
    """
    probe_ports = [80, 443, 22, 445, 139, 3389]
    start = time.monotonic()
    for port in probe_ports:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return (time.monotonic() - start) * 1000
        except (asyncio.TimeoutError, ConnectionRefusedError):
            # ConnectionRefused means the host IS alive, port is just closed
            if isinstance(sys.exc_info()[1], ConnectionRefusedError):
                return (time.monotonic() - start) * 1000
            continue
        except OSError:
            continue
    return None


async def icmp_ping(ip: str, timeout: float) -> Optional[float]:
    """
    Fallback: uses the OS `ping` command (as an async subprocess) for
    more accurate discovery. Not guaranteed to work everywhere, but
    many systems allow unprivileged ICMP.
    """
    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", str(int(timeout) or 1), ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
        if proc.returncode == 0:
            return (time.monotonic() - start) * 1000
    except Exception:
        pass
    return None


async def discover_host(ip: str, timeout: float, use_icmp: bool) -> HostResult:
    result = HostResult(ip=ip)
    rtt = await is_host_alive(ip, timeout)
    if rtt is None and use_icmp:
        rtt = await icmp_ping(ip, timeout)
    if rtt is not None:
        result.alive = True
        result.response_time_ms = round(rtt, 2)
        try:
            result.hostname = socket.getfqdn(ip)
            if result.hostname == ip:
                result.hostname = ""
        except Exception:
            pass
    return result


# ----------------------------------------------------------------------------
# 2) Port Scanning (async + semaphore to control concurrency)
# ----------------------------------------------------------------------------
async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       port: int, timeout: float) -> str:
    """Tries to grab a simple banner from the service (e.g. HTTP header or SSH version)."""
    try:
        if port in (80, 8080, 8000, 8888):
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=timeout)
        if data:
            text = data.decode(errors="ignore").strip().split("\n")[0]
            return text[:100]
    except Exception:
        pass
    return ""


async def scan_port(ip: str, port: int, timeout: float,
                     grab: bool, sem: asyncio.Semaphore) -> Optional[PortResult]:
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        service = COMMON_SERVICE_NAMES.get(port, "")
        banner = ""
        if grab:
            banner = await grab_banner(reader, writer, port, timeout)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return PortResult(port=port, state="open", service=service, banner=banner)


async def scan_host_ports(ip: str, ports: List[int], timeout: float,
                           concurrency: int, grab: bool,
                           progress_cb=None) -> List[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_port(ip, p, timeout, grab, sem) for p in ports]
    results = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        if progress_cb:
            progress_cb(done, len(tasks))
        if r:
            results.append(r)
    results.sort(key=lambda x: x.port)
    return results


# ----------------------------------------------------------------------------
# Parsing helpers - convert input formats (CIDR / range / single IP) to a list of IPs
# ----------------------------------------------------------------------------
def parse_targets(target: str) -> List[str]:
    target = target.strip()
    if "/" in target:  # CIDR: 192.168.1.0/24
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    if "-" in target:  # Range: 192.168.1.1-192.168.1.50 or 192.168.1.1-50
        start_str, end_str = target.split("-", 1)
        start_ip = ipaddress.ip_address(start_str.strip())
        if "." in end_str:
            end_ip = ipaddress.ip_address(end_str.strip())
        else:
            parts = start_str.strip().split(".")
            parts[-1] = end_str.strip()
            end_ip = ipaddress.ip_address(".".join(parts))
        result = []
        cur = int(start_ip)
        end = int(end_ip)
        while cur <= end:
            result.append(str(ipaddress.ip_address(cur)))
            cur += 1
        return result
    return [target]  # single IP


def parse_ports(ports_str: str) -> List[int]:
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


# ----------------------------------------------------------------------------
# Main orchestration
# ----------------------------------------------------------------------------
async def run_scan(args) -> List[HostResult]:
    targets = parse_targets(args.target)
    print(f"[*] Target hosts: {len(targets)}")

    # Step 1: Host discovery
    print("[*] Starting host discovery...")
    disc_sem = asyncio.Semaphore(args.concurrency)

    async def discover_with_sem(ip):
        async with disc_sem:
            return await discover_host(ip, args.timeout, args.icmp)

    t0 = time.monotonic()
    host_results = await asyncio.gather(*(discover_with_sem(ip) for ip in targets))
    alive_hosts = [h for h in host_results if h.alive]
    print(f"[+] Live hosts found: {len(alive_hosts)} "
          f"(took {time.monotonic() - t0:.1f}s)")

    if not alive_hosts:
        return host_results

    # Step 2: Port scanning on live hosts only
    if args.top_ports:
        ports = TOP_PORTS
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = TOP_PORTS

    print(f"[*] Scanning {len(ports)} ports on each live host...")
    for host in alive_hosts:
        t0 = time.monotonic()

        def progress(done, total):
            print(f"\r    {host.ip}: {done}/{total} ports scanned...", end="", flush=True)

        host.open_ports = await scan_host_ports(
            host.ip, ports, args.timeout, args.concurrency, args.grab_banner,
            progress_cb=progress if args.verbose else None,
        )
        print(f"\r    {host.ip}: scan finished in {time.monotonic() - t0:.1f}s - "
              f"{len(host.open_ports)} open ports" + " " * 20)

    return host_results


def print_report(results: List[HostResult]):
    print("\n" + "=" * 60)
    print("Final Scan Report")
    print("=" * 60)
    for host in results:
        if not host.alive:
            continue
        name = f" ({host.hostname})" if host.hostname else ""
        print(f"\nHost: {host.ip}{name}  —  response time: {host.response_time_ms} ms")
        if not host.open_ports:
            print("    No open ports found in the scanned range.")
        for p in host.open_ports:
            svc = f" [{p.service}]" if p.service else ""
            banner = f"  -> {p.banner}" if p.banner else ""
            print(f"    - {p.port}/tcp  OPEN{svc}{banner}")
    print()


def save_json(results: List[HostResult], path: str):
    data = [asdict(h) for h in results]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] Results saved to: {path}")


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="High-efficiency network scanner (Host Discovery + Port Scan) using asyncio",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="IP / CIDR (192.168.1.0/24) / range (192.168.1.1-50)")
    p.add_argument("-p", "--ports", default=None,
                   help="Ports: 80,443 or 1-1024. Defaults to top-ports if not set")
    p.add_argument("--top-ports", action="store_true",
                   help="Scan the top ~100 common ports (default behavior)")
    p.add_argument("-c", "--concurrency", type=int, default=300,
                   help="Number of concurrent connections (default: 300)")
    p.add_argument("-t", "--timeout", type=float, default=0.8,
                   help="Timeout in seconds per connection (default: 0.8)")
    p.add_argument("--icmp", action="store_true",
                   help="Use ICMP ping as a fallback for host discovery")
    p.add_argument("-b", "--grab-banner", action="store_true",
                   help="Try to grab a banner from each open port")
    p.add_argument("-o", "--output", default=None, help="Save results to a JSON file")
    p.add_argument("-v", "--verbose", action="store_true", help="Show live scan progress")
    return p

def run():
    print("=" * 60)
    print("Network Scanner")
    print("=" * 60)

    target = input("Target (IP / CIDR / Range) > ").strip()

    ports = input(
        "Ports (e.g. 22,80,443 or 1-1024) [Press Enter for Top Ports]: "
    ).strip()

    class Args:
        pass

    args = Args()
    args.target = target
    args.ports = ports if ports else None
    args.top_ports = not bool(ports)
    args.concurrency = 300
    args.timeout = 0.8
    args.icmp = False
    args.grab_banner = False
    args.output = None
    args.verbose = False

    try:
        results = asyncio.run(run_scan(args))
        print_report(results)

        if args.output:
            save_json(results, args.output)

    except KeyboardInterrupt:
        print("\n[!] تم إيقاف الفحص من المستخدم.")

    input("\nPress Enter to continue...")


def main():
    args = build_arg_parser().parse_args()

    print("=" * 60)
    print("Network Scanner")
    print("=" * 60)

    try:
        results = asyncio.run(run_scan(args))
        print_report(results)

        if args.output:
            save_json(results, args.output)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()