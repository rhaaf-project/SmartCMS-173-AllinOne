$ErrorActionPreference = "Stop"

Write-Host "🚀 SmartCMS VISTO - Optimized Deployment Script" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# 1. Build Angular
Write-Host "`n📦 Building Angular Project..." -ForegroundColor Yellow
npm run build
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed!"; exit 1 }

# 2. Create Optimized Archive (Excluding heavy assets)
Write-Host "`n🗜️ Creating Optimized Archive (deploy.tar.gz)..." -ForegroundColor Yellow
# Exclude assets/images folder entirely (flags, user-profiles, etc. rarely change)
tar -czvf deploy.tar.gz -C dist . --exclude "assets/images"

# 3. Upload Archive and Scripts
Write-Host "`n📤 Uploading to Server (103.154.80.171)..." -ForegroundColor Yellow
scp deploy.tar.gz api.php db_ucx_schema.sql root@103.154.80.171:/var/www/html/SmartCMS-Visto/

# 4. Extract on Server
Write-Host "`n📂 Extracting on Server..." -ForegroundColor Yellow
ssh root@103.154.80.171 "cd /var/www/html/SmartCMS-Visto/ && tar -xzvf deploy.tar.gz && rm deploy.tar.gz && chown -R www-data:www-data ."

# 5. Sync Database Structure (Schema Only)
# To sync FULL DATA (erase server data), run: 
# ./deploy.ps1 -FullDataSync
Write-Host "`n🔄 Syncing Database Schema (Structure only)..." -ForegroundColor Yellow
ssh root@103.154.80.171 "mysql -u root db_ucx < /var/www/html/SmartCMS-Visto/db_ucx_schema.sql"

Write-Host "`n✅ Deployment Completed Successfully!" -ForegroundColor Green
Write-Host "👉 URL: http://103.154.80.171/SmartCMS/"
