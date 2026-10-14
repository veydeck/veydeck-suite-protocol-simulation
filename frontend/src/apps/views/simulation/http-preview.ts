/**
 * @file http-preview.ts
 * @description HTTP 仿真规则首屏预览的默认内容与解析逻辑。
 */

/** 未配置自定义页面时使用的 Nginx 仿真欢迎页。 */
export const DEFAULT_NGINX_PREVIEW_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Welcome to nginx!</title>
<style>
    html { color-scheme: light dark; }
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; padding: 2em; background-color: #f8fafc; color: #1e293b; }
    h1 { color: #0f172a; font-size: 2em; margin-bottom: 0.5em; }
    p { line-height: 1.5; }
    a { color: #3b82f6; text-decoration: none; }
    a:hover { text-decoration: underline; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;

/**
 * 解析 HTTP 规则的首屏 HTML，空值回退到内置 Nginx 欢迎页。
 * @param value 规则配置中的 HTML 字段。
 * @returns 可直接交给受限 iframe 渲染的 HTML。
 */
export function resolveHttpPreviewHtml(value: unknown): string {
  return typeof value === "string" && value.trim()
    ? value
    : DEFAULT_NGINX_PREVIEW_HTML;
}
