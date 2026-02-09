# Deployment Analysis & Guide for Future Gemini Agents

**Date:** 2026-02-04
**Project:** SmartCMS VISTO (Angular)
**Server:** 103.154.80.171
**Root Path:** `D:\02____WORKS\04___Server\Projects\CMS\VISTO\CMS`

## 🚀 Successful Deployment Strategy: Manual Build + SCP

Since the server directory `/var/www/html/SmartCMS-Visto` is **NOT a git repository**, standard `git pull` deployment **fails**. We must use the **Manual Build & Upload** strategy.

### 📋 Steps that WORKED:

1.  **Cleanup First**: 
    - Delete unused heavy assets (e.g., `src/assets/images/flags` removed to speed up upload).
    - Ensure `dist` folder is clean (`npm run build`).

2.  **Build Locally**:
    ```powershell
    npm run build
    ```

3.  **Package (Compress)**:
    - Compress `dist` content to `deploy.tar.gz` to preserve structure and speed/reliability of upload.
    - *Avoid copying thousands of small files individually via SCP.*
    ```powershell
    tar -czvf deploy.tar.gz -C dist .
    ```

4.  **Upload (SCP)**:
    ```powershell
    scp deploy.tar.gz root@103.154.80.171:/var/www/html/SmartCMS-Visto/
    scp api.php root@103.154.80.171:/var/www/html/SmartCMS-Visto/
    ```

5.  **Extract & Clean on Server**:
    ```powershell
    ssh root@103.154.80.171 "cd /var/www/html/SmartCMS-Visto/ && tar -xzvf deploy.tar.gz && rm deploy.tar.gz && chown -R www-data:www-data ."
    ```

### 🛑 Issues & Blockers Encountered:

*   **"fatal: not a git repository"**: The server folder contains only build artifacts, not source code with `.git`. 
    *   **Fix:** **Do NOT try `git pull` on server.** Use the SCP method above.
*   **Permissions**: `run_command` via PowerShell SSH sometimes has escaping issues. Simple commands work best.
*   **Database Risk**: Do **NOT** run auto-sync database scripts (like in `deploy.ps1`) unless there are schema changes. It risks overwriting production data. 
    *   **Check:** Verify `api.php` usually requires `$dbname = 'db_ucx'` (same as local).

### ✅ Critical Checks Before Deploy:

1.  **API Config**: Ensure local `api.php` has correct DB credentials (usually root/no-pass for local, but check strictness on server. Currently code is shared and works).
2.  **Server Path**: Verify destination path. Current valid path: `/var/www/html/SmartCMS-Visto/`.
3.  **Visual Check**: Build success locally does not guarantee runtime success. Check console for "Template not found" if deleting files.

### 💡 Recommendation for Future Agents:

*   **Always check server state first:** `ssh root@... "ls -la /path/"` to see if it's a git repo or build folder.
*   **Prefer SCP/Tarball**: Faster and safer for non-git deployments.
*   **Respect "Standardization"**: If updating icons/UI, ensure consistency across *all* modules (grep search is your friend).
