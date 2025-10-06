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