# MySQL Scanner (Censys Internship Take-Home)

This Go program detects whether **MySQL** is running on a specified host and port by performing a **single handshake read** over TCP — no authentication or login required.  
It parses key fields (protocol version, server version, connection ID, etc.) directly from the MySQL wire protocol.

---

## Setup

### 1. Prerequisites
- **Go 1.18+** installed  
    ```bash
    go version
    ```

- Clone & Build
    ```bash
    git clone https://github.com/hadimalik12/censys_take_home_exercise_data_internship.git
    cd censys_take_home_exercise_data_internship
    go mod tidy
    go build -o mysql_scout

### 2. Testing with Docker
1. Start a MySQL test container
    ```bash
    docker run --rm -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root --name mysql mysql:8
    ```
    Wait ~10-20 seconds until MySQL is ready (docker logs mysql shows "ready for connections")

2. Run the scanner against it
    ```bash
    # Basic detection
    ./mysql_scout -host 127.0.0.1 -port 3306
    # Verbose mode (shows capabilities and plugin info)
    ./mysql_scout -host 127.0.0.1 -port 3306 -v
    ```
