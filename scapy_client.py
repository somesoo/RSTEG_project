from scapy_class import TCPClient

def get_vars(a=0):
    if a:
        cover_file_path = input("Input cover file path: ")
        secret_file_path = input("Input secret file path: ")
        server_ip = input("Input server IP: ")
        dest_port = int(input("Input destination port: "))
        rsteg_prob = int(input("Input RSTEG probability: "))
        return cover_file_path, secret_file_path, server_ip, dest_port, rsteg_prob
    else:
        file_path = input("Input file path: ")
        server_ip = input("Input server IP: ")
        dest_port = int(input("Input destination port: "))
        return file_path, server_ip, dest_port

def welcome_prompt():
    print("Welcome to the RSTEG implementation!")

    while True:
        user_input = input("Do you want to proceed, and send RSETG? (Y/N, default is N): ").strip().lower()

        # Check user input
        if not user_input:
            return False
        elif user_input in ['y', 'yes']:
            print("Please input RSTEG parameters")
            return True
        elif user_input in ['n', 'no']:
            print("Please input normal trasmision parameters")
            return False
        else:
            print("Invalid input. Please enter 'Y' or 'N'.")


if __name__ == "__main__":
    # Example usage:
    # Start the client
    # Call the function
    user_wants_to_proceed = welcome_prompt()

    # Use the user's response
    if user_wants_to_proceed:
        cover_file_path, secret_file_path, server_ip, dest_port, rsteg_prob = get_vars(1)
        client = TCPClient(target_ip=server_ip, target_port=dest_port, file_path=cover_file_path, secret_path=secret_file_path)
        client.send_secret_file(rsteg_prob)
    else:
        file_path, server_ip, dest_port = get_vars()
        client = TCPClient(target_ip=server_ip, target_port=dest_port, file_path=file_path, secret_path=None)
        client.send_large_file()