---
description: Deploy SmartCMS VISTO to production server (no approval needed)
---

# Deploy SmartCMS VISTO

Deploy Angular build to server 103.154.80.171 without public images.

// turbo-all

## Steps

1. Build Angular project
```bash
npm run build
```

2. Create tar archive (without images)
```bash
tar -czvf deploy.tar.gz -C dist . --exclude="assets/images"
```

3. Upload to server
```bash
scp deploy.tar.gz root@103.154.80.171:/var/www/html/SmartCMS-Visto/
```

4. Extract on server and cleanup
```bash
ssh root@103.154.80.171 "cd /var/www/html/SmartCMS-Visto/ && tar -xzf deploy.tar.gz && rm deploy.tar.gz && chown -R www-data:www-data ."
```

## Notes
- Server: 103.154.80.171
- Path: /var/www/html/SmartCMS-Visto/
- Images are excluded (already on server)