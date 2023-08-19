package Util;


import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.Authenticator;
import okhttp3.Credentials;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.Route;
import okio.BufferedSink;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Map;

public class HttpUtil {


    private static final OkHttpClient client = getInsecureOkHttpClient();

    private static OkHttpClient getInsecureOkHttpClient() {
        try {
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier((hostname, session) -> true);

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static Response get(String url, Map<String, String> headers, ProxyConfig proxyConfig) throws IOException {
        Request.Builder requestBuilder = new Request.Builder().url(url);

        // 添加请求头
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                requestBuilder.addHeader(header.getKey(), header.getValue());
            }
        }

        Request request = requestBuilder.build();
        OkHttpClient.Builder clientBuilder = client.newBuilder();

        // 如果设置了代理
        if (proxyConfig != null) {
            clientBuilder.proxy(proxyConfig.getProxy());
            if (proxyConfig.getUsername() != null && proxyConfig.getPassword() != null) {
                clientBuilder.proxyAuthenticator(proxyConfig.getAuthenticator());
            }
        }

        return clientBuilder.build().newCall(request).execute();
    }

    public static Response post(String url, Map<String, String> headers, RequestBody body, ProxyConfig proxyConfig) throws IOException {
        Request.Builder requestBuilder = new Request.Builder().url(url).post(body);

        // 添加请求头
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                requestBuilder.addHeader(header.getKey(), header.getValue());
            }
        }

        Request request = requestBuilder.build();
        OkHttpClient.Builder clientBuilder = client.newBuilder();

        // 如果设置了代理
        if (proxyConfig != null) {
            clientBuilder.proxy(proxyConfig.getProxy());
            if (proxyConfig.getUsername() != null && proxyConfig.getPassword() != null) {
                clientBuilder.proxyAuthenticator(proxyConfig.getAuthenticator());
            }
        }

        return clientBuilder.build().newCall(request).execute();
    }

    public static Response post(String url, Map<String, String> headers, InputStream inputStream, MediaType mediaType, ProxyConfig proxyConfig) throws IOException {
        RequestBody requestBody = createRequestBodyFromStream(inputStream, mediaType);
        return post(url, headers, requestBody, proxyConfig);
    }

    public static RequestBody createRequestBodyFromStream(final InputStream inputStream, final MediaType mediaType) {
        return new RequestBody() {
            @Override
            public MediaType contentType() {
                return mediaType;
            }

            @Override
            public long contentLength() {
                try {
                    return inputStream.available();
                } catch (IOException e) {
                    return 0;
                }
            }

            @Override
            public void writeTo(BufferedSink sink) throws IOException {
                sink.writeAll(okio.Okio.source(inputStream));
            }
        };
    }

    // 代理配置类
    public static class ProxyConfig {
        private final Proxy proxy;
        private final String username;
        private final String password;

        public ProxyConfig(Proxy.Type type, String hostname, int port, String username, String password) {
            this.proxy = new Proxy(type, new InetSocketAddress(hostname, port));
            this.username = username;
            this.password = password;
        }

        public Proxy getProxy() {
            return proxy;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public Authenticator getAuthenticator() {
            return new Authenticator() {
                @Override
                public Request authenticate(Route route, Response response) throws IOException {
                    String credential = Credentials.basic(username, password);
                    return response.request().newBuilder().header("Proxy-Authorization", credential).build();
                }
            };
        }
    }
}
