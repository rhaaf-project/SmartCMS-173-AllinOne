# PowerShell SSH Escaping Cheat Sheet

## Problem
PowerShell interprets special chars (`$`, `"`, `@`, `&&`) differently than bash.

## Solutions

### 1. SCP + Run Script (RECOMMENDED)
```powershell
# Create script locally, upload, run
scp script.sh root@server:/tmp/
ssh root@server "chmod +x /tmp/script.sh; /tmp/script.sh"
```

### 2. Heredoc with 'EOF' (single quotes)
```powershell
ssh root@server "cat > /tmp/script.sql << 'SQLEOF'
UPDATE users SET password='value' WHERE email='test@test.com';
SQLEOF
mysql db_ucx < /tmp/script.sql"
```

### 3. Avoid PowerShell && 
```powershell
# WRONG - PowerShell doesn't support &&
ssh root@server "cmd1 && cmd2"

# RIGHT - Use semicolon
ssh root@server "cmd1; cmd2"
```

### 4. Use Backticks for $ in PowerShell
```powershell
# PowerShell interpolates $var, escape with backtick
ssh root@server "echo `$2y`$10`$hash"
```

## Special Characters to Avoid
| Char | Issue | Solution |
|------|-------|----------|
| $ | Variable expansion | `\$` or backtick |
| @ | Splatting | Base64 encode |
| " | Quote nesting | Heredoc |
| && | Not valid PS | Use ; |
