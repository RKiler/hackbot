# Production drop-ins

These files document the deployed service wiring without including secret
values. Paths to environment and credential files are intentional; the files
they reference are private runtime state and must not be committed.

- `backup-key.conf`: loads the private backup-key environment file.
- `burp-bridge.conf`: supplies the Burp bridge through systemd credentials.
- `recon-reader.conf`: loads the read-only recon connection environment.
- `resources.conf`: constrains CPU, memory, tasks, and file descriptors.
- `storage-mount.conf`: requires the block volume before startup.

Review host-specific paths before installing these examples on another system.
