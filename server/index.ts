import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import multer from "multer";
import { createServer as createViteServer } from "vite";

const PORT = Number(process.env.PORT || 5000);
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const MAX_RULES_PER_TYPE = 20;
const MAX_ENGINE_OUTPUT_BYTES = 2 * 1024 * 1024;
const ENGINE_TIMEOUT_MS = 60_000;
const DOWNLOAD_TTL_MS = 15 * 60_000;
const MAX_PENDING_DOWNLOADS = 20;
const ENGINE_PATH = path.resolve(
  process.cwd(),
  process.platform === "win32" ? "build/dpi_engine.exe" : "build/dpi_engine",
);
const APPLICATIONS = new Set([
  "Unknown",
  "HTTP",
  "HTTPS",
  "DNS",
  "TLS",
  "QUIC",
  "Google",
  "Facebook",
  "YouTube",
  "Twitter/X",
  "Instagram",
  "Netflix",
  "Amazon",
  "Microsoft",
  "Apple",
  "WhatsApp",
  "Telegram",
  "TikTok",
  "Spotify",
  "Zoom",
  "Discord",
  "GitHub",
  "Cloudflare",
]);

type PcapInfo = {
  records: number;
  byteOrder: "little" | "big";
  snaplen: number;
};

type EngineStats = {
  totalPackets: number;
  totalBytes: number;
  tcpPackets: number;
  udpPackets: number;
  forwarded: number;
  dropped: number;
};

type ApplicationStat = {
  name: string;
  count: number;
  percent: number;
};

type DetectedDomain = {
  domain: string;
  application: string;
  status: string;
};

type BlockingRule = {
  type: "IP" | "Application" | "Domain";
  value: string;
  status: string;
};

type BlockingInputs = {
  ips: string[];
  apps: string[];
  domains: string[];
};

type DownloadEntry = {
  directory: string;
  filePath: string;
  fileName: string;
  expiresAt: number;
};

type EngineResult = {
  stdout: string;
  stderr: string;
};

class EngineProcessError extends Error {
  stdout: string;
  stderr: string;
  timedOut: boolean;

  constructor(
    message: string,
    stdout: string,
    stderr: string,
    timedOut = false,
  ) {
    super(message);
    this.name = "EngineProcessError";
    this.stdout = stdout;
    this.stderr = stderr;
    this.timedOut = timedOut;
  }
}

const downloads = new Map<string, DownloadEntry>();
const app = express();
app.disable("x-powered-by");

function getPcapByteOrder(buffer: Buffer): PcapInfo["byteOrder"] | null {
  const magic = buffer.subarray(0, 4).toString("hex");
  if (magic === "d4c3b2a1") return "little";
  if (magic === "a1b2c3d4") return "big";
  return null;
}

function readPcapInfo(buffer: Buffer): PcapInfo {
  if (buffer.length < 24) {
    throw new Error(
      "The upload is too short to contain a complete PCAP header.",
    );
  }

  const byteOrder = getPcapByteOrder(buffer);
  if (!byteOrder) {
    throw new Error(
      "Unsupported capture format. Upload a classic microsecond .pcap file (PCAPNG and nanosecond PCAP are not supported).",
    );
  }

  const read16 =
    byteOrder === "little"
      ? (offset: number) => buffer.readUInt16LE(offset)
      : (offset: number) => buffer.readUInt16BE(offset);
  const read32 =
    byteOrder === "little"
      ? (offset: number) => buffer.readUInt32LE(offset)
      : (offset: number) => buffer.readUInt32BE(offset);

  const major = read16(4);
  const minor = read16(6);
  const snaplen = read32(16);
  const linkType = read32(20);

  if (major !== 2 || minor !== 4) {
    throw new Error(
      `Unsupported PCAP version ${major}.${minor}; this engine expects version 2.4.`,
    );
  }
  if (snaplen === 0 || snaplen > 65_535) {
    throw new Error("The PCAP snap length must be between 1 and 65,535 bytes.");
  }
  if (linkType !== 1) {
    throw new Error(
      "This engine expects Ethernet (link type 1) PCAP captures.",
    );
  }

  let offset = 24;
  let records = 0;
  while (offset < buffer.length) {
    if (buffer.length - offset < 16) {
      throw new Error(`The PCAP ends inside packet record ${records + 1}.`);
    }

    const includedLength = read32(offset + 8);
    const originalLength = read32(offset + 12);
    if (
      includedLength > snaplen ||
      includedLength > 65_535 ||
      includedLength > originalLength
    ) {
      throw new Error(
        `Packet record ${records + 1} has invalid captured/original lengths.`,
      );
    }
    offset += 16;
    if (includedLength > buffer.length - offset) {
      throw new Error(`Packet record ${records + 1} is truncated.`);
    }
    offset += includedLength;
    records += 1;
  }

  return { records, byteOrder, snaplen };
}

function parseRuleValues(value: unknown, label: string): string[] {
  const values = Array.isArray(value)
    ? value
    : value === undefined
      ? []
      : [value];
  const rules = values.flatMap((item) => {
    if (typeof item !== "string") {
      throw new Error(`${label} rules must be text.`);
    }
    return item
      .split(/[\n,]/)
      .map((part) => part.trim())
      .filter(Boolean);
  });

  if (rules.length > MAX_RULES_PER_TYPE) {
    throw new Error(
      `You can provide at most ${MAX_RULES_PER_TYPE} ${label.toLowerCase()} rules.`,
    );
  }
  return rules;
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => {
      if (!/^(0|[1-9]\d{0,2})$/.test(part)) return false;
      const octet = Number(part);
      return octet <= 255;
    })
  );
}

function parseBlockingInputs(body: Request["body"]): BlockingInputs {
  const ips = parseRuleValues(body?.blockIps, "IP");
  const apps = parseRuleValues(body?.blockApps, "Application");
  const domains = parseRuleValues(body?.blockDomains, "Domain");

  if (ips.some((ip) => !isIpv4(ip))) {
    throw new Error("Each blocked IP must be a valid IPv4 address.");
  }
  if (apps.some((name) => !APPLICATIONS.has(name))) {
    throw new Error(
      `Application names must match the engine's exact labels: ${[...APPLICATIONS].join(", ")}.`,
    );
  }
  if (
    domains.some((domain) => domain.length > 253 || !/^[\w.*-]+$/u.test(domain))
  ) {
    throw new Error(
      "Blocked domains must be 1–253 letters, numbers, dots, underscores, asterisks, or hyphens.",
    );
  }

  return { ips, apps, domains };
}

function parseEngineStats(stdout: string): EngineStats {
  const labels: Array<[keyof EngineStats, string]> = [
    ["totalPackets", "Total Packets"],
    ["totalBytes", "Total Bytes"],
    ["tcpPackets", "TCP Packets"],
    ["udpPackets", "UDP Packets"],
    ["forwarded", "Forwarded"],
    ["dropped", "Dropped"],
  ];
  const stats = {} as EngineStats;

  for (const [key, label] of labels) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = stdout.match(new RegExp(`${escaped}:\\s*(\\d+)`));
    if (!match) {
      throw new Error(`The engine report did not include "${label}".`);
    }
    const value = Number(match[1]);
    if (!Number.isSafeInteger(value)) {
      throw new Error(`The engine reported an invalid value for "${label}".`);
    }
    stats[key] = value;
  }

  if (stats.tcpPackets + stats.udpPackets !== stats.totalPackets) {
    throw new Error(
      "The engine report has inconsistent TCP, UDP, and total packet counts.",
    );
  }
  if (stats.forwarded + stats.dropped !== stats.totalPackets) {
    throw new Error(
      "The engine report has inconsistent forwarded and dropped packet counts.",
    );
  }
  return stats;
}

function parseApplications(stdout: string): ApplicationStat[] {
  const marker = "APPLICATION BREAKDOWN";
  const start = stdout.indexOf(marker);
  if (start < 0)
    throw new Error(
      "The engine report did not include its application breakdown.",
    );

  const section = stdout.slice(start).split("[Detected Domains/SNIs]")[0];
  const applications: ApplicationStat[] = [];
  for (const line of section.split(/\r?\n/)) {
    const match = line.match(/^\s*║\s+(.+?)\s+(\d+)\s+(\d+(?:\.\d+)?)%\s+/u);
    if (!match) continue;
    applications.push({
      name: match[1].trim(),
      count: Number(match[2]),
      percent: Number(match[3]),
    });
  }
  return applications;
}

function parseDetectedDomains(
  stdout: string,
  rules: BlockingInputs,
): DetectedDomain[] {
  const marker = "[Detected Domains/SNIs]";
  const start = stdout.indexOf(marker);
  if (start < 0) return [];

  const domains: DetectedDomain[] = [];
  for (const line of stdout.slice(start + marker.length).split(/\r?\n/)) {
    const match = line.match(/^\s*-\s+(.+?)\s+->\s+(.+?)\s*$/u);
    if (!match) continue;
    const domain = match[1].trim();
    const application = match[2].trim();
    const matchesDomain = rules.domains.some((rule) => domain.includes(rule));
    const matchesApp = rules.apps.includes(application);
    let status =
      "Detected; the engine does not report a per-domain block outcome";
    if (matchesDomain) status = "Matches a configured domain substring rule";
    else if (matchesApp) status = "Matches a configured application rule";
    domains.push({ domain, application, status });
  }
  return domains;
}

function describeBlockingRules(
  rules: BlockingInputs,
  dropped: number,
): BlockingRule[] {
  const outcome =
    dropped === 0
      ? "Passed to engine; 0 packets dropped overall"
      : `Passed to engine; ${dropped} packets dropped overall (per-rule counts unavailable)`;
  return [
    ...rules.ips.map((value) => ({
      type: "IP" as const,
      value,
      status: outcome,
    })),
    ...rules.apps.map((value) => ({
      type: "Application" as const,
      value,
      status: outcome,
    })),
    ...rules.domains.map((value) => ({
      type: "Domain" as const,
      value,
      status: outcome,
    })),
  ];
}

function runEngine(args: string[]): Promise<EngineResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(ENGINE_PATH, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let outputLimitExceeded = false;

    const terminate = () => {
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminate();
    }, ENGINE_TIMEOUT_MS);

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_ENGINE_OUTPUT_BYTES) {
        outputLimitExceeded = true;
        terminate();
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_ENGINE_OUTPUT_BYTES) {
        outputLimitExceeded = true;
        terminate();
        return;
      }
      stderr.push(chunk);
    });

    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(
        new EngineProcessError(
          `Could not start the DPI engine: ${error.message}`,
          Buffer.concat(stdout).toString("utf8"),
          Buffer.concat(stderr).toString("utf8"),
        ),
      );
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      const captured = {
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      };
      if (timedOut) {
        reject(
          new EngineProcessError(
            `DPI analysis exceeded the ${ENGINE_TIMEOUT_MS / 1000}-second execution limit.`,
            captured.stdout,
            captured.stderr,
            true,
          ),
        );
      } else if (outputLimitExceeded) {
        reject(
          new EngineProcessError(
            "The engine produced too much diagnostic output.",
            captured.stdout,
            captured.stderr,
          ),
        );
      } else if (code !== 0) {
        reject(
          new EngineProcessError(
            `DPI engine exited with code ${code ?? signal ?? "unknown"}.`,
            captured.stdout,
            captured.stderr,
          ),
        );
      } else {
        resolve(captured);
      }
    });
  });
}

function safeFileStem(originalName: string): string {
  const base = path.basename(originalName, path.extname(originalName));
  const cleaned = base
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 70);
  return cleaned || "capture";
}

function removeDownload(id: string): void {
  const entry = downloads.get(id);
  if (!entry) return;
  downloads.delete(id);
  void rm(entry.directory, { recursive: true, force: true }).catch(
    (error: unknown) => {
      console.error("Temporary download cleanup failed:", error);
    },
  );
}

async function cleanupAbandonedAnalysisDirectories(): Promise<void> {
  const entries = await readdir(tmpdir(), { withFileTypes: true });
  const analysisDirectories = entries.filter(
    (entry) => entry.isDirectory() && entry.name.startsWith("dpi-analysis-"),
  );
  await Promise.all(
    analysisDirectories.map((entry) =>
      rm(path.join(tmpdir(), entry.name), { recursive: true, force: true }),
    ),
  );
}

function purgeExpiredDownloads(): void {
  const now = Date.now();
  for (const [id, entry] of downloads) {
    if (entry.expiresAt <= now) removeDownload(id);
  }
}

const downloadCleanup = setInterval(purgeExpiredDownloads, 60_000);
downloadCleanup.unref();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_UPLOAD_BYTES,
    files: 1,
    fields: 30,
    fieldSize: 4096,
    parts: 31,
  },
});

app.get("/api/health", (_request, response) => {
  response.json({
    status: "ok",
    engineBuilt: true,
    maxUploadBytes: MAX_UPLOAD_BYTES,
    acceptedFormat: "classic PCAP 2.4, Ethernet, microsecond timestamps",
  });
});

app.post("/api/analyze", upload.single("file"), async (request, response) => {
  let temporaryDirectory: string | undefined;
  let keepOutputForDownload = false;

  try {
    purgeExpiredDownloads();
    if (downloads.size >= MAX_PENDING_DOWNLOADS) {
      response
        .status(429)
        .json({
          error:
            "Too many filtered captures are waiting for download. Download a result and try again.",
        });
      return;
    }

    const file = request.file;
    if (!file) {
      response
        .status(400)
        .json({ error: 'Attach a .pcap file using the "file" field.' });
      return;
    }
    if (path.extname(file.originalname).toLowerCase() !== ".pcap") {
      response
        .status(400)
        .json({ error: "Upload a file with the .pcap extension." });
      return;
    }
    try {
      readPcapInfo(file.buffer);
    } catch (error) {
      response
        .status(400)
        .json({
          error: error instanceof Error ? error.message : "Invalid PCAP file.",
        });
      return;
    }

    let rules: BlockingInputs;
    try {
      rules = parseBlockingInputs(request.body);
    } catch (error) {
      response
        .status(400)
        .json({
          error:
            error instanceof Error ? error.message : "Invalid blocking rules.",
        });
      return;
    }

    temporaryDirectory = await mkdtemp(path.join(tmpdir(), "dpi-analysis-"));
    const inputPath = path.join(temporaryDirectory, "input.pcap");
    const outputPath = path.join(temporaryDirectory, "filtered-output.pcap");
    await writeFile(inputPath, file.buffer, { flag: "wx" });

    const args = [inputPath, outputPath];
    for (const ip of rules.ips) args.push("--block-ip", ip);
    for (const application of rules.apps) args.push("--block-app", application);
    for (const domain of rules.domains) args.push("--block-domain", domain);

    let engine: EngineResult;
    try {
      engine = await runEngine(args);
    } catch (error) {
      if (error instanceof EngineProcessError) {
        response.status(error.timedOut ? 504 : 502).json({
          error: error.message,
          engineOutput: [
            error.stdout,
            error.stderr ? `[stderr]\n${error.stderr}` : "",
          ]
            .filter(Boolean)
            .join("\n"),
        });
        return;
      }
      throw error;
    }

    let stats: EngineStats;
    let applications: ApplicationStat[];
    try {
      stats = parseEngineStats(engine.stdout);
      applications = parseApplications(engine.stdout);
      if (stats.totalPackets > 0 && applications.length === 0) {
        throw new Error(
          "The engine report did not include parseable application statistics.",
        );
      }
    } catch (error) {
      response.status(502).json({
        error:
          error instanceof Error
            ? error.message
            : "Could not parse the engine report.",
        engineOutput: [
          engine.stdout,
          engine.stderr ? `[stderr]\n${engine.stderr}` : "",
        ]
          .filter(Boolean)
          .join("\n"),
      });
      return;
    }

    const outputBuffer = await readFile(outputPath);
    const outputInfo = readPcapInfo(outputBuffer);
    if (outputInfo.records !== stats.forwarded) {
      response.status(502).json({
        error: `Engine output mismatch: the report says ${stats.forwarded} packets were forwarded, but the generated PCAP contains ${outputInfo.records} records.`,
        engineOutput: [
          engine.stdout,
          engine.stderr ? `[stderr]\n${engine.stderr}` : "",
        ]
          .filter(Boolean)
          .join("\n"),
      });
      return;
    }

    await rm(inputPath, { force: true });
    const id = randomUUID();
    const downloadFileName = `${safeFileStem(file.originalname)}-filtered.pcap`;
    downloads.set(id, {
      directory: temporaryDirectory,
      filePath: outputPath,
      fileName: downloadFileName,
      expiresAt: Date.now() + DOWNLOAD_TTL_MS,
    });
    keepOutputForDownload = true;

    const engineOutput = [
      engine.stdout,
      engine.stderr ? `[stderr]\n${engine.stderr}` : "",
    ]
      .filter(Boolean)
      .join("\n");
    response.json({
      fileName: file.originalname,
      fileSizeBytes: file.size,
      ...stats,
      applications,
      detectedDomains: parseDetectedDomains(engine.stdout, rules),
      blockedTraffic: describeBlockingRules(rules, stats.dropped),
      engineOutput,
      outputPcapRecords: outputInfo.records,
      outputPcapBytes: outputBuffer.length,
      downloadUrl: `/api/download/${id}`,
      downloadExpiresInSeconds: DOWNLOAD_TTL_MS / 1000,
      notes: [
        "The engine does not emit per-rule or per-domain packet drop counts; dropped is the actual engine-wide total.",
        ...(rules.domains.length
          ? ["Domain rules use case-sensitive substring matching."]
          : []),
        ...(rules.apps.length
          ? ["Application rules use exact, case-sensitive engine labels."]
          : []),
      ],
    });
  } catch (error) {
    console.error("PCAP analysis request failed:", error);
    if (!response.headersSent) {
      response
        .status(500)
        .json({
          error:
            "The analysis request failed before a result could be returned.",
        });
    }
  } finally {
    if (temporaryDirectory && !keepOutputForDownload) {
      await rm(temporaryDirectory, { recursive: true, force: true }).catch(
        (error: unknown) => {
          console.error("Temporary analysis cleanup failed:", error);
        },
      );
    }
  }
});

app.get("/api/download/:id", (request, response) => {
  const id = request.params.id;
  if (!/^[\da-f-]{36}$/iu.test(id)) {
    response.status(404).json({ error: "Filtered PCAP not found or expired." });
    return;
  }

  const entry = downloads.get(id);
  if (!entry || entry.expiresAt <= Date.now()) {
    if (entry) removeDownload(id);
    response.status(404).json({ error: "Filtered PCAP not found or expired." });
    return;
  }

  response.download(entry.filePath, entry.fileName, (error) => {
    removeDownload(id);
    if (error && !response.headersSent) {
      response.status(500).json({ error: "Could not send the filtered PCAP." });
    }
  });
});

const errorHandler = (
  error: unknown,
  _request: Request,
  response: Response,
  _next: NextFunction,
) => {
  if (error instanceof multer.MulterError) {
    const message =
      error.code === "LIMIT_FILE_SIZE"
        ? `The PCAP exceeds the ${MAX_UPLOAD_BYTES / (1024 * 1024)} MiB upload limit.`
        : error.message;
    response.status(400).json({ error: message });
    return;
  }
  console.error("Unhandled request error:", error);
  response.status(500).json({ error: "An unexpected server error occurred." });
};

app.use(errorHandler);

const httpServer: HttpServer = createServer(app);

async function start(): Promise<void> {
  await mkdir(path.dirname(ENGINE_PATH), { recursive: true });
  const engineStat = await stat(ENGINE_PATH).catch(() => null);
  if (!engineStat?.isFile()) {
    throw new Error(
      `DPI engine binary is missing at ${ENGINE_PATH}; run npm run build:engine first.`,
    );
  }
  await cleanupAbandonedAnalysisDirectories();

  if (process.env.NODE_ENV === "production") {
    const clientDirectory = path.resolve(process.cwd(), "dist/client");
    app.use(express.static(clientDirectory, { maxAge: "1h", index: false }));
    app.use((request: Request, response: Response, next: NextFunction) => {
      if (request.method !== "GET" || request.path.startsWith("/api/")) {
        next();
        return;
      }
      response.sendFile(path.join(clientDirectory, "index.html"), (error) => {
        if (error && !response.headersSent) next(error);
      });
    });
  } else {
    const vite = await createViteServer({
      configFile: path.resolve(process.cwd(), "vite.config.ts"),
      appType: "custom",
      server: {
        middlewareMode: true,
        allowedHosts: true,
        hmr: { server: httpServer },
      },
    });
    app.use(vite.middlewares);
    app.use(
      async (request: Request, response: Response, next: NextFunction) => {
        if (request.method !== "GET" || request.path.startsWith("/api/")) {
          next();
          return;
        }
        try {
          const template = await readFile(
            path.resolve(process.cwd(), "index.html"),
            "utf8",
          );
          const html = await vite.transformIndexHtml(
            request.originalUrl,
            template,
          );
          response.status(200).type("html").send(html);
        } catch (error) {
          vite.ssrFixStacktrace(error as Error);
          next(error);
        }
      },
    );
  }

  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`Network Packet Analyzer listening on 0.0.0.0:${PORT}`);
  });
}

start().catch((error: unknown) => {
  console.error("Application startup failed:", error);
  process.exitCode = 1;
});
