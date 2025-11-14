# DuckDB StorageBox Extension

A hybrid filesystem extension for Hetzner Storage Boxes that combines the best features of WebDAV and SSH protocols.

## Status

**Functional** - This extension provides a hybrid filesystem implementation that uses:

- SSH for directory operations (more efficient than WebDAV's recursive MKCOL)
- WebDAV for file operations (efficient HTTP range requests for Parquet files)

## Architecture

The extension provides a `storagebox://` protocol handler with:

### Hybrid Protocol Selection

- **Directory Creation**: Uses SSH `mkdir -p` for efficient recursive directory creation
- **Directory Listing**: Uses SSH `tree -J` command for fast recursive file listing
- **File Move/Rename**: Uses SFTP native rename operation for atomic server-side moves
- **File Writes**: Uses HTTP PUT to upload 10MB chunks as `.part` files, then SSH `dd` to combine them
- **File Reads/Deletes**: Uses HTTP GET and DELETE for file access
- **Connection Pooling**: Maintains persistent SSH connections to avoid handshake overhead

### Key Features

- Multi-part streaming uploads (10MB chunks) to minimize memory usage
- Automatic chunk combining via SSH `dd` command on file close
- Efficient HTTP range requests for reading Parquet files
- Basic authentication with username/password via DuckDB secrets
- Optional SSH key authentication support

### Why Hybrid?

The hybrid approach provides the best performance characteristics:

- **SSH/SFTP for directory and metadata operations**:
  - `mkdir -p` creates all parent directories in a single command (WebDAV requires recursive MKCOL requests, one per directory level)
  - `tree -J` provides fast recursive file listing with JSON output (WebDAV requires multiple PROPFIND requests for deep directory structures)
  - SFTP native rename for atomic file moves (WebDAV MOVE requires HTTP round-trips)
  - `dd` command combines uploaded chunks into final file (avoids large memory buffers)

- **HTTP for file data operations**:
  - Chunked uploads via HTTP PUT (10MB chunks) minimize memory usage
  - HTTP range requests for reading small chunks from large Parquet files
  - Simple HTTP DELETE for file removal

- **Connection pooling**: SSH connections are pooled and reused, minimizing the handshake overhead while still benefiting from SSH's efficient directory operations.

## Building

```bash
make release GEN=ninja
```

## Configuration

### Basic Authentication (Password)

```sql
-- Create secret with username and password
CREATE SECRET hetzner_storage (
    TYPE STORAGEBOX,
    USERNAME 'u508112',
    PASSWORD 'your_password',
    SCOPE 'storagebox://u508112'
);
```

### SSH Key Authentication

```sql
-- Create secret with SSH key path
CREATE SECRET hetzner_storage (
    TYPE STORAGEBOX,
    USERNAME 'u508112',
    PASSWORD 'your_password',
    KEY_PATH '/path/to/ssh/key',
    PORT 23,
    SCOPE 'storagebox://u508112'
);
```

### Usage

```sql
-- Copy data to StorageBox
COPY (
    SELECT * FROM '/path/to/local/file.csv'
) TO 'storagebox://u508112/remote/file.parquet';

-- Read from StorageBox
SELECT * FROM 'storagebox://u508112/remote/file.parquet' LIMIT 10;
```

## Development

This extension is based on:

- [duckdb-webdav](https://github.com/midwork-finds-jobs/duckdb-webdav) - WebDAV filesystem support
- [duckdb-sshfs](https://github.com/midwork-finds-jobs/duckdb-sshfs) - SSH/SFTP filesystem support

See SPEC.md for the full specification.

## License

MIT
