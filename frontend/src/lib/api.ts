// API 客户端薄壳:JSON 请求 + 401 统一回调(登录闸)+ 错误即后端原文。
// 纪律:错误文案不包装——后端如实中文报错,前端原样呈现。

export class ApiError extends Error {
  status: number;
  constructor(status: number, msg: string) {
    super(msg);
    this.status = status;
  }
}

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const resp = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  if (resp.status === 401) {
    onUnauthorized?.();
    throw new ApiError(401, "未登录或会话已过期");
  }
  const text = await resp.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    if (!resp.ok) throw new ApiError(resp.status, text || `HTTP ${resp.status}`);
    throw new ApiError(resp.status, "响应非 JSON(如实): " + text.slice(0, 200));
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, data.error || `HTTP ${resp.status}`);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => req<T>("GET", path),
  post: <T>(path: string, body?: unknown) => req<T>("POST", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => req<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => req<T>("PATCH", path, body ?? {}),
  del: <T>(path: string, body?: unknown) => req<T>("DELETE", path, body),
};

// PUT 二进制分块(上传专用,不走 JSON)。
export async function putChunk(
  path: string,
  data: ArrayBuffer,
): Promise<void> {
  const resp = await fetch(path, {
    method: "PUT",
    body: data,
    credentials: "same-origin",
  });
  if (resp.status === 401) {
    onUnauthorized?.();
    throw new ApiError(401, "未登录或会话已过期");
  }
  if (!resp.ok) {
    const text = await resp.text();
    let msg = `HTTP ${resp.status}`;
    try {
      msg = JSON.parse(text).error || msg;
    } catch {
      if (text) msg = text.slice(0, 300);
    }
    throw new ApiError(resp.status, msg);
  }
}

// ---- 工作空间文件管理器(multipart 上传 / 附件下载,不走 JSON 壳) ----

// wsBase 工作区 API 基址(切片十三,案件隔离):caseID 非空=案件工作区
// (/api/cases/{id}/workspace/*),空=未分配遗留区(旧全局 /api/workspace/*)。
export function wsBase(caseID?: string): string {
  return caseID
    ? `/api/cases/${encodeURIComponent(caseID)}/workspace`
    : "/api/workspace";
}

// workspaceUpload 多文件上传到指定目录(path 为相对根的 slash 路径)。
export async function workspaceUpload(
  path: string,
  files: File[],
  caseID?: string,
): Promise<{ uploaded: number }> {
  const fd = new FormData();
  fd.append("path", path);
  for (const f of files) fd.append("files", f, f.name);
  const resp = await fetch(`${wsBase(caseID)}/upload`, {
    method: "POST",
    body: fd,
    credentials: "same-origin",
  });
  if (resp.status === 401) {
    onUnauthorized?.();
    throw new ApiError(401, "未登录或会话已过期");
  }
  const text = await resp.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new ApiError(resp.status, "响应非 JSON(如实): " + text.slice(0, 200));
  }
  if (!resp.ok) throw new ApiError(resp.status, data.error || `HTTP ${resp.status}`);
  return data as { uploaded: number };
}

// workspaceDownload 附件下载(blob → a[download],中文名走后端
// Content-Disposition;这里用条目名兜底)。
export async function workspaceDownload(
  path: string,
  name: string,
  caseID?: string,
): Promise<void> {
  const resp = await fetch(
    `${wsBase(caseID)}/download?path=${encodeURIComponent(path)}`,
    { credentials: "same-origin" },
  );
  if (resp.status === 401) {
    onUnauthorized?.();
    throw new ApiError(401, "未登录或会话已过期");
  }
  if (!resp.ok) {
    const text = await resp.text();
    let msg = `HTTP ${resp.status}`;
    try {
      msg = JSON.parse(text).error || msg;
    } catch {
      if (text) msg = text.slice(0, 300);
    }
    throw new ApiError(resp.status, msg);
  }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

// ---- 案件封存包导出/导入(M4;登录即可,不走 JSON 壳) ----

// importCase 导入封存包(multipart 字段 file;202 + {case:{id,name}, sources})。
export async function importCase(
  file: File,
): Promise<{ case: { id: string; name: string }; sources: number }> {
  const fd = new FormData();
  fd.append("file", file, file.name);
  const resp = await fetch("/api/cases/import", {
    method: "POST",
    body: fd,
    credentials: "same-origin",
  });
  if (resp.status === 401) {
    onUnauthorized?.();
    throw new ApiError(401, "未登录或会话已过期");
  }
  const text = await resp.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new ApiError(resp.status, "响应非 JSON(如实): " + text.slice(0, 200));
  }
  if (!resp.ok) throw new ApiError(resp.status, data.error || `HTTP ${resp.status}`);
  return data as { case: { id: string; name: string }; sources: number };
}

// exportCase 导出封存包(application/zip → a[download],照 workspaceDownload
// 范式;文件名从 Content-Disposition 取,取不到用兜底名)。
export async function exportCase(caseID: string, fallbackName: string): Promise<void> {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseID)}/export`, {
    credentials: "same-origin",
  });
  if (resp.status === 401) {
    onUnauthorized?.();
    throw new ApiError(401, "未登录或会话已过期");
  }
  if (!resp.ok) {
    const text = await resp.text();
    let msg = `HTTP ${resp.status}`;
    try {
      msg = JSON.parse(text).error || msg;
    } catch {
      if (text) msg = text.slice(0, 300);
    }
    throw new ApiError(resp.status, msg);
  }
  const blob = await resp.blob();
  let name = fallbackName;
  const cd = resp.headers.get("Content-Disposition") || "";
  const star = /filename\*=(?:UTF-8|utf-8)''([^;]+)/.exec(cd);
  const plain = /filename="?([^";]+)"?/.exec(cd);
  if (star) {
    try {
      name = decodeURIComponent(star[1].trim());
    } catch {
      name = star[1].trim();
    }
  } else if (plain) {
    name = plain[1].trim();
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
