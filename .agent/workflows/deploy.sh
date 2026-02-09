#!/bin/bash

# 1. Upload file
echo "Uploading..."
scp deploy.tar.gz root@103.154.80.171:/var/www/html/SmartCMS-Visto/

# 2. Extract & Cleanup di Server
echo "Extracting..."
ssh root@103.154.80.171 "cd /var/www/html/SmartCMS-Visto/ && tar -xzf deploy.tar.gz && rm deploy.tar.gz && chown -R www-data:www-data ."

echo "Done!"