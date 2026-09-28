// postbuild:vite build 清空 dist 后把占位页放回去——
// internal/webui/dist/placeholder.html 是唯一入库文件(未构建时二进制服务它,
// 如实提示);源文件在 frontend/placeholder.html,此处只拷贝。
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "placeholder.html");
const dst = join(here, "..", "..", "internal", "webui", "dist", "placeholder.html");
mkdirSync(dirname(dst), { recursive: true });
copyFileSync(src, dst);
console.log("postbuild: placeholder.html 已放回 internal/webui/dist");
