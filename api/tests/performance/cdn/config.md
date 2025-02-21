# CDN Configuration Guide

## CloudFront Setup
- Origin Configuration:
  - Origin Domain: panel.example.com
  - Protocol Policy: HTTPS Only
  - SSL Certificate: Custom SSL (ACM)

## Origin Configuration
```nginx
# Origin Server Settings
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# Cache Control Headers
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 30d;
    add_header Cache-Control "public, no-transform";
}
