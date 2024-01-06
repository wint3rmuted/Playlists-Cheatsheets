import socket

def print_banner():
    # ASCII art banner
    banner = """
    
    _/                              _/_/_/                             v.2         
   _/_/_/      _/_/_/  _/_/_/    _/          _/_/_/    _/_/_/  _/_/_/    
  _/    _/  _/    _/  _/    _/    _/_/    _/        _/    _/  _/    _/   
 _/    _/  _/    _/  _/    _/        _/  _/        _/    _/  _/    _/    
_/_/_/      _/_/_/  _/    _/  _/_/_/      _/_/_/    _/_/_/  _/    _/     

================ >> Portscanner & Bannergrabber by wint3rmute ༼ ༎ຶ ᆺ ༎ຶ༽  
                                                                    
    """

    print(banner)

def get_user_input():
    target_host = input("Enter the target host (e.g., example.com): ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    return target_host, start_port, end_port

def port_scan_and_banner(target, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    if open_ports:
        print(f"Open ports on {target}: {open_ports}")
        print("Banner information for open ports:")
        for port in open_ports:
            banner = banner_grab(target, port)
            print(f"Port {port}: {banner}")
    else:
        print(f"No open ports found on {target} in the specified range.")

def banner_grab(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8').strip()
        sock.close()
        return banner
    except:
        return "Banner not available"

if __name__ == "__main__":
    print_banner()
    target_host, start_port, end_port = get_user_input()
    port_scan_and_banner(target_host, start_port, end_port)
