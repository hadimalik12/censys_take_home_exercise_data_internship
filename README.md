# MySQL Scanner (Censys Internship Take-Home Exercise)

This Go program detects whether **MySQL** is running on a specified host and port by performing a **single handshake read** over TCP — no authentication or login required.  
It parses key fields (protocol version, server version, connection ID, etc.) directly from the MySQL wire protocol.

---

## Setup

### 1. Prerequisites
- **Go 1.18+** installed  
    ```bash
    go version
    ```

### 2. Clone & Build
- 
    ```bash
    git clone https://github.com/hadimalik12/censys_take_home_exercise_data_internship.git
    cd censys_take_home_exercise_data_internship
    go mod tidy
    go build -o mysql_scout
    ```

## Testing with Docker
### 1. Start a MySQL test container
- 
    ```bash
    docker run --rm -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root --name mysql mysql:8
    ```
    Wait ~10-20 seconds until MySQL is ready (docker logs mysql shows "ready for connections")

### 2. Run the scanner against it
- 
    ```bash
    # Basic detection
    ./mysql_scout -host 127.0.0.1 -port 3306
    # Verbose mode (shows capabilities and plugin info)
    ./mysql_scout -host 127.0.0.1 -port 3306 -v
    ```
    
    Example output (basic):
-
    ```json
    {"ok":true,"mysql":true,"server_version":"8.4.6","protocol":10,"connection_id":10}
    ```
    

    Example output (verbose):
-
    ```json
    {"ok":true,"mysql":true,"protocol":10,"server_version":"8.4.6","connection_id":10,"capability_flags":3758096383,"character_set":255,"status_flags":2,"auth_plugin":"caching_sha2_password","preview_hex":"490000000a382e342e36000a000000372f57253907084a00ffffff0200ffdf15000000000000000000006d514e625f1e7571025e4d5e0063616368696e675f73"}
    ```

### 3. Stop the container
-
    ```bash
    docker stop mysql
    ```
    (The --rm flag automatically removes it afterward.)

## Author
**Hadi Malik**  
GitHub: [@hadimalik12](https://github.com/hadimalik12)  
Email: hadia7549@gmail.com



