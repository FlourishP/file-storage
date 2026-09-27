# File Storage Service

File upload, storage, and CDN delivery service with virus scanning and access control.

## Features
- **Upload**: Multi-part file upload with progress tracking
- **Virus Scanning**: Automated malware detection on upload
- **Access Control**: Signed URLs with expiry and permission levels
- **CDN Delivery**: Optimized delivery via CDN integration
- **Thumbnails**: Auto-generated image thumbnails
- **Versioning**: File version history and rollback

## Tech Stack
- **Backend**: Node.js, Express, TypeScript
- **Storage**: MinIO (S3-compatible)
- **Cache**: Redis
- **Scanning**: ClamAV
- **Auth**: JWT

## Quick Start
```bash
git clone https://github.com/FlourishP/file-storage
cd file-storage
npm install
docker-compose up -d
npm start
```

## License
MIT — see [LICENSE](LICENSE)
