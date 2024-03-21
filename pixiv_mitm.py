from mitmproxy import http
from mitmproxy.proxy import server_hooks




class PixivProxy:
    def request(self, flow: http.HTTPFlow) -> None:
        flow.request.scheme = 'https'
        flow.request.port = 443

    def response(self, flow: http.HTTPFlow) -> None:
        if "Set-Cookie" in flow.response.headers:
            # 移除 Set-Cookie 的 Secure 属性
            cookies = flow.response.headers.get_all("Set-Cookie")
            for i, cookie in enumerate(cookies):
                cookies[i] = cookie.replace("secure;", "").strip()
                cookies[i] = cookie.replace("secure", "").strip()
            flow.response.headers.set_all("set-cookie", cookies)
        if 'Location' in flow.response.headers:
            flow.response.headers.set_all("Location",
                                          [flow.response.headers.get("Location").replace("https:", "http:")])
        flow.response.text = flow.response.text.replace("https:", "http:")

    def server_connect(self, flow: server_hooks.ServerConnectionHookData):
        sni = str(flow.server.sni)
        if sni.endswith('pixiv.net'):
            flow.server.sni = None
            flow.server.address = ('210.140.131.221', 443)
        if sni == 'i.pximg.net':
            flow.server.sni = None
            flow.server.address = ('210.140.92.142', 443)


addons = [
    PixivProxy(),
]
