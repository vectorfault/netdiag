# netdiag

`netdiag` is a lightweight Windows command-line utility that collects
basic host and network diagnostics and outputs JSON or human-readable text.

## Examples

```powershell
netdiag
netdiag -Format text
netdiag -IncludePublicIp
netdiag -IncludeListeningPorts
