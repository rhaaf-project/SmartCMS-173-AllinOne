#!/bin/bash
# Init Git and push to SmartCMS-173-AllinOne repo

cd /var/www/SmartCMS-173

# Init git
git init

# Create .gitignore
cat > .gitignore << 'EOF'
node_modules/
dist/
.angular/
*.log
.DS_Store
*.tar.gz
EOF

# Config git user
git config user.email "rhaaf@smartcms.local"
git config user.name "SmartCMS Admin"

# Add all files
git add .

# Initial commit
git commit -m "Initial checkpoint - 2026-02-09 working state"

# Add remote and push
git remote add origin https://github.com/rhaaf-project/SmartCMS-173-AllinOne.git
git branch -M main
git push -u origin main

echo "Done! Pushed to GitHub"
