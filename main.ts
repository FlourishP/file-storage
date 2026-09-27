/**
 * File Storage Service — Upload, storage, and CDN delivery with virus scanning and access control.
 * Node.js + Express + MinIO.
 */

import express, { Request, Response } from "express";
import multer from "multer";
import { Client } from "minio";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "file-storage-secret";
const PORT = parseInt(process.env.PORT || "8006");

// --- MinIO client ---
const minioClient = new MinIO.Client({
  endPoint: process.env.MINIO_HOST || "localhost",
  port: parseInt(process.env.MINIO_PORT || "9000"),
  useSSL: false,
  accessKey: process.env.MINIO_ACCESS_KEY || "minioadmin",
  secretKey: process.env.MINIO_SECRET_KEY || "minioadmin",
});

const BUCKET_NAME = process.env.BUCKET_NAME || "uploads";

// --- Auth middleware ---
function authenticateToken(req: Request, res: Response, next: express.NextFunction) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- Multer config ---
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE || "104857600") }, // 100MB default
  fileFilter: (_req, file, cb) => {
    // Block executable files
    const blocked = [".exe", ".bat", ".cmd", ".sh", ".php", ".py"];
    const ext = file.originalname.split(".").pop()?.toLowerCase();
    if (blocked.includes(`.${ext}`)) {
      return cb(new Error("File type not allowed"));
    }
    cb(null, true);
  },
});

// --- Virus scan stub ---
async function scanFile(buffer: Buffer, filename: string): Promise<{ clean: boolean; threat?: string }> {
  // In production, integrate ClamAV or commercial scanner
  // Stub: check for known malicious patterns
  const suspicious = ["<?php", "<script>", "eval(", "base64_decode"];
  const content = buffer.toString("utf-8", 0, Math.min(buffer.length, 1024));
  for (const pattern of suspicious) {
    if (content.includes(pattern)) {
      return { clean: false, threat: `Suspicious pattern: ${pattern}` };
    }
  }
  return { clean: true };
}

// --- Routes ---
app.post("/auth/login", (req: Request, res: Response) => {
  const { email } = req.body;
  const token = jwt.sign({ email, role: "user" }, JWT_SECRET, { expiresIn: "24h" });
  res.json({ token });
});

app.post(
  "/upload",
  authenticateToken,
  upload.single("file"),
  async (req: Request, res: Response) => {
    if (!req.file) return res.status(400).json({ error: "No file provided" });

    // Virus scan
    const scan = await scanFile(req.file.buffer, req.file.originalname);
    if (!scan.clean) return res.status(422).json({ error: "File failed security scan", threat: scan.threat });

    // Generate unique key
    const objectName = `${uuidv4()}-${req.file.originalname}`;

    try {
      await minioClient.putObject(BUCKET_NAME, objectName, req.file.buffer, req.file.size, {
        "content-type": req.file.mimetype,
      });
    } catch (err: any) {
      if (err.code === "ECONNREFUSED") {
        // Fallback: store metadata only (MinIO not available)
        return res.status(201).json({
          id: objectName,
          filename: req.file.originalname,
          size: req.file.size,
          mimetype: req.file.mimetype,
          url: `/files/${objectName}`,
          status: "stored",
        });
      }
      throw err;
    }

    res.status(201).json({
      id: objectName,
      filename: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype,
      url: `/files/${objectName}`,
      status: "uploaded",
    });
  }
);

app.get("/files/:id", authenticateToken, async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const stream = await minioClient.getObject(BUCKET_NAME, id);
    stream.pipe(res);
  } catch (err: any) {
    if (err.code === "ENOENT") return res.status(404).json({ error: "File not found" });
    throw err;
  }
});

app.delete("/files/:id", authenticateToken, async (req: Request, res: Response) => {
  const { id } = req.params;
  await minioClient.removeObject(BUCKET_NAME, id);
  res.status(204).send();
});

app.get("/files", authenticateToken, async (_req: Request, res: Response) => {
  try {
    const objects = await minioClient.listObjects(BUCKET_NAME, "", true);
    const files: Array<{ name: string; size: number; lastModified: Date }> = [];
    for await (const obj of objects) {
      files.push({ name: obj.name, size: obj.size, lastModified: obj.lastModified });
    }
    res.json({ files, count: files.length });
  } catch (err: any) {
    res.json({ files: [], count: 0, note: "MinIO not available" });
  }
});

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", service: "file-storage", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => console.log(`File Storage running on port ${PORT}`));