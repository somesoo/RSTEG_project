from scapy_class import TCPServer 

if __name__ == "__main__":
    print("Welcome to the RSTEG implementation!")

    print("This is server script, it will start listening on port: (Ctrl+C to break)): ")
    print("Please input RSTEG parameters")
    server_ip = input("Input server IP address (default: 10.0.2.15): ")
    port = input("Input server source port (default: 65432): ")
    if port=="":
        port=65432
    else:
        port = int(port)
    print(type(port), port)
    # Start the server
    server = TCPServer(ip=server_ip, port=port)
    server.start()