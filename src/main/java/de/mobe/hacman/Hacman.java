package de.mobe.hacman;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class Hacman {

    private static final Logger LOG = LoggerFactory.getLogger(Hacman.class);

    public static class RemoteHack {

        public static final String META_CONTENT = "content";
        public static final String META_NAME_CSRF = "meta[name='_csrf']";

        public String startHac() {

            BasicCookieStore cookieStore = new BasicCookieStore();
            HttpClientContext httpContext = HttpClientContext.create();
            httpContext.setAttribute(HttpClientContext.COOKIE_STORE, cookieStore);

            try (CloseableHttpClient httpclient = createAcceptSelfSignedCertificateClient()) {
                String csrfToken = loginAndGetToken(httpclient, httpContext);
                String newCsrfToken = loginAndPostCredentials(httpclient, httpContext, csrfToken);
                executeScript(newCsrfToken, httpContext, httpclient);
            } catch (IOException | ParseException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
                e.printStackTrace();
            }

            return "";
        }

        private String loginAndPostCredentials(final CloseableHttpClient httpClient, final HttpClientContext httpContext, final String csrftoken)
            throws IOException, ParseException {
            List<NameValuePair> urlParameters;

            Cookie cookie = httpContext.getCookieStore().getCookies().get(0);

            HttpPost post = new HttpPost(getLoginSubmitUrl());

            post.setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0");
            post.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
            post.setHeader("Accept-Language", "en-US,en;q=0.5");
            post.setHeader("Accept-Encoding", "gzip, deflate, br");
            post.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            post.setHeader("Origin", "https://localhost:9002");
            post.setHeader("DNT", "1");
            post.setHeader("Connection", "keep-alive");
            post.setHeader("Referer", "https://localhost:9002/hac/login");
            post.setHeader("Cookie", getCookie(cookie));
            post.setHeader("Upgrade-Insecure-Requests", "1");
            post.setHeader("Sec-Fetch-Dest", "document");
            post.setHeader("Sec-Fetch-Mode", "navigate");
            post.setHeader("Sec-Fetch-Site", "same-origin");
            post.setHeader("Sec-Fetch-User", "?1");

            // add request parameters or form parameters
            urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("j_username", "admin"));
            urlParameters.add(new BasicNameValuePair("j_password", "nimda"));
            urlParameters.add(new BasicNameValuePair("_csrf", csrftoken));

            post.setEntity(new UrlEncodedFormEntity(urlParameters));

            CloseableHttpResponse response = httpClient.execute(post, httpContext);

            String body = EntityUtils.toString(response.getEntity());

            Document doc = Jsoup.parse(body);

            Elements metaTag = doc.select(META_NAME_CSRF);

            String newCsrftoken = metaTag.first().attr(META_CONTENT);

            return newCsrftoken;
        }

        private String loginAndGetToken(final CloseableHttpClient httpClient, final HttpClientContext httpContext)
            throws IOException, ParseException {
            HttpGet httpget = new HttpGet(getLoginUrl());
            LOG.info("Executing request {}", httpget.getRequestUri());
            CloseableHttpResponse response = httpClient.execute(httpget, httpContext);
            String body = EntityUtils.toString(response.getEntity());
            Document doc = Jsoup.parse(body);
            Elements metaTag = doc.select(META_NAME_CSRF);
            return metaTag.first().attr(META_CONTENT);
        }

        private CloseableHttpClient createAcceptSelfSignedCertificateClient()
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
            return
                HttpClients.custom()
                           .setConnectionManager(
                               PoolingHttpClientConnectionManagerBuilder
                                   .create()
                                   .setSSLSocketFactory(
                                       SSLConnectionSocketFactoryBuilder
                                           .create()
                                           .setSslContext(
                                               SSLContextBuilder
                                                   .create()
                                                   .loadTrustMaterial(
                                                       TrustAllStrategy.INSTANCE)
                                                   .build())
                                           .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                                           .build())
                                   .build())
                           .build();
        }

        private String getHost() {
            return "https://127.0.0.1:9002";
        }

        private String getLoginUrl() {
            return String.format("%s/%s", getHost(),"hac/login");
        }

        private String getLoginSubmitUrl() {
            return String.format("%s/%s", getHost(),"hac/j_spring_security_check");
        }

        private String getUsername() {
            return "admin";
        }

        private String getPassword() {
            return getPassword();
        }

    }

    public void main(String[] args) {

        RemoteHack remoteHack = new RemoteHack();

        remoteHack.startHac();

        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext httpContext = HttpClientContext.create();
        httpContext.setAttribute(HttpClientContext.COOKIE_STORE, cookieStore);

        try (CloseableHttpClient httpclient = createAcceptSelfSignedCertificateClient()) {

            HttpGet httpget = new HttpGet("https://127.0.0.1:9002/hac/login");
            LOG.info("Executing request {}", httpget.getRequestUri());

            CloseableHttpResponse response = httpclient.execute(httpget, httpContext);

            String body = EntityUtils.toString(response.getEntity());

            Document doc = Jsoup.parse(body);

            Elements metalinksParam = doc.select("meta[name='_csrf']");

            String csrftoken = metalinksParam.first().attr("content");

            LOG.info(csrftoken + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

            HttpPost post;
            List<NameValuePair> urlParameters;
            Cookie cookie = httpContext.getCookieStore().getCookies().get(0);

            ////////////////////////////////////////////////////////////////////////////////////
            post = new HttpPost("https://127.0.0.1:9002/hac/j_spring_security_check");
            post.setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0");
            post.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
            post.setHeader("Accept-Language", "en-US,en;q=0.5");
            post.setHeader("Accept-Encoding", "gzip, deflate, br");
            post.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            post.setHeader("Origin", "https://localhost:9002");
            post.setHeader("DNT", "1");
            post.setHeader("Connection", "keep-alive");
            post.setHeader("Referer", "https://localhost:9002/hac/login");
            post.setHeader("Cookie", getCookie(cookie));
            post.setHeader("Upgrade-Insecure-Requests", "1");
            post.setHeader("Sec-Fetch-Dest", "document");
            post.setHeader("Sec-Fetch-Mode", "navigate");
            post.setHeader("Sec-Fetch-Site", "same-origin");
            post.setHeader("Sec-Fetch-User", "?1");

            // add request parameters or form parameters
            urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("j_username", "admin"));
            urlParameters.add(new BasicNameValuePair("j_password", "nimda"));
            urlParameters.add(new BasicNameValuePair("_csrf", csrftoken));

            post.setEntity(new UrlEncodedFormEntity(urlParameters));

            response = httpclient.execute(post, httpContext);

            body = EntityUtils.toString(response.getEntity());

            doc = Jsoup.parse(body);

            metalinksParam = doc.select("meta[name='_csrf']");

            String csrftoken2 = metalinksParam.first().attr("content");

          //  LOG.info(EntityUtils.toString(response.getEntity())); //NOSONAR

            executeScript(csrftoken2, httpContext, httpclient);

        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException | IOException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    static void executeScript(String csrftoken, HttpClientContext httpContext, CloseableHttpClient httpclient)
        throws IOException, ParseException {
        //String fileName = "hello.txt";
        String fileName = "crontab.txt";

        URL url = Hacman.class
            .getClassLoader()
            .getResource(fileName);

        LOG.info(csrftoken + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        String script = asString(url.openStream());

        Cookie cookie = httpContext.getCookieStore().getCookies().get(0);

        HttpPost post = new HttpPost("https://127.0.0.1:9002/hac/console/scripting/execute");

        post.setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0");
        post.setHeader("X-CSRF-TOKEN", csrftoken);
        post.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        post.setHeader("Accept", "application/json");
        post.setHeader("Accept-Language", "en-US,en;q=0.5");
        post.setHeader("Accept-Encoding", "gzip, deflate, br");
        post.setHeader("X-Requested-With", "XMLHttpRequest");
        post.setHeader("Origin", "https://localhost:9002");
        post.setHeader("DNT", "1");
        post.setHeader("Connection", "keep-alive");
        post.setHeader("Referer", "https://localhost:9002/hac/console/scripting");
        post.setHeader("Sec-Fetch-Dest", "empty");
        post.setHeader("Sec-Fetch-Mode", "cors");
        post.setHeader("Sec-Fetch-Site", "same-origin");
        post.setHeader("Cookie", getCookie(cookie));

        List<NameValuePair> urlParameters;

        urlParameters = new ArrayList<>();
        urlParameters.add(new BasicNameValuePair("scriptType", "groovy"));
        urlParameters.add(new BasicNameValuePair("commit", "false"));
        urlParameters.add(new BasicNameValuePair("script", script));
        post.setEntity(new UrlEncodedFormEntity(urlParameters));
        CloseableHttpResponse response = httpclient.execute(post, httpContext);

        LOG.info(EntityUtils.toString(response.getEntity())); //NOSONAR
    }

    private static CloseableHttpClient createAcceptSelfSignedCertificateClient()
        throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return
            HttpClients.custom()
                       .setConnectionManager(
                           PoolingHttpClientConnectionManagerBuilder
                               .create()
                               .setSSLSocketFactory(
                                   SSLConnectionSocketFactoryBuilder
                                       .create()
                                       .setSslContext(
                                           SSLContextBuilder
                                               .create()
                                               .loadTrustMaterial(
                                                   TrustAllStrategy.INSTANCE)
                                               .build())
                                       .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                                       .build())
                               .build())
                       .build();
    }

    private static String encodeValue(final String value) throws UnsupportedEncodingException {

        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
        LOG.error(encoded);
        return encoded;

    }

    private static String asString(final InputStream inputStream) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        for (int length; (length = inputStream.read(buffer)) != -1; ) {
            result.write(buffer, 0, length);
        }
        return result.toString(StandardCharsets.UTF_8.name());
    }

    private static String getCookie(Cookie cookie) {
        return cookie.getName() + "=" + cookie.getValue();
    }
}

/**
 * JS  3BCF10E6E6DE8EEBE2F7E0F2D67A6613    d13f55fb-5e8b-4b3c-9368-0fd54f10d211
 *
 *   620843F825CCE3783F9761516341A5BA     408b53e4-b2b4-4ee8-9614-2a92d2dd6556
 */