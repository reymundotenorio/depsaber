import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../dist");
const basePath = "/depsaber/";
const port = Number(process.env.PORT ?? 4174);

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/depsaber") {
      response.writeHead(308, { Location: basePath });
      response.end();
      return;
    }
    if (!url.pathname.startsWith(basePath)) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found\n");
      return;
    }

    const relativePath = decodeURIComponent(url.pathname.slice(basePath.length)) || "index.html";
    const filePath = resolve(root, relativePath);
    if (!isInsideRoot(filePath)) {
      response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Bad request\n");
      return;
    }

    const resolvedPath = await resolveStaticFile(filePath);
    if (!resolvedPath) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found\n");
      return;
    }

    response.writeHead(200, {
      "Content-Type": contentTypes.get(extname(resolvedPath)) ?? "application/octet-stream",
    });
    createReadStream(resolvedPath).pipe(response);
  } catch (error) {
    response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    response.end(`${error instanceof Error ? error.message : "Unexpected error"}\n`);
  }
});

server.on("error", (error) => {
  console.error(`DepSaber Pages preview failed: ${error instanceof Error ? error.message : "Unexpected error"}`);
  process.exitCode = 1;
});

server.listen(port, "127.0.0.1", () => {
  console.log(`DepSaber Pages preview: http://127.0.0.1:${port}${basePath}`);
});

function isInsideRoot(filePath) {
  const pathFromRoot = relative(root, filePath);
  return pathFromRoot === "" || (!pathFromRoot.startsWith("..") && !pathFromRoot.includes(`..${sep}`));
}

async function resolveStaticFile(filePath) {
  try {
    const fileStat = await stat(filePath);
    if (fileStat.isDirectory()) {
      return join(filePath, "index.html");
    }
    return fileStat.isFile() ? filePath : null;
  } catch {
    return extname(filePath) === "" ? join(root, "index.html") : null;
  }
}
