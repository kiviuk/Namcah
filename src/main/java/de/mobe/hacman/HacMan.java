package de.mobe.hacman;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
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
import org.apache.hc.core5.util.Timeout;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class HacMan {

    private static final Logger LOG = LoggerFactory.getLogger(HacMan.class);

    private static final String META_CONTENT = "content";
    private static final String META_NAME_CSRF = "meta[name='_csrf']";
    private static final String HAC_LOGIN = "hac/login";
    private static final String HAC_J_SPRING_SECURITY_CHECK = "hac/j_spring_security_check";
    private static final String HAC_CONSOLE_SCRIPTING_EXECUTE = "hac/console/scripting/execute";
    private static final String URL_PATH_PATTERN = "{0}/{1}";
    private static final String ADMIN = "admin";
    private static final String ADMIN_PWD = StringUtils.reverse(ADMIN);
    private static final String HTTPS_127_0_0_1_9002 = "https://127.0.0.1:9002";
    private static final Timeout CONNECTION_TIMEOUT_MS = Timeout.of(10, TimeUnit.SECONDS);
    private static final long CANCEL_HAC_MAN_AFTER_MS = 60L * 1000 * 100;
    private static final Map<HttpUriRequestBase, Long> REQUEST_MONITOR = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService SCHEDULER = Executors.newScheduledThreadPool(1);
    private static final int OK = 0;
    private static final int ERROR = 1;

    public static final String VOID_SCRIPT_RESULT = "void";

    static {
        SCHEDULER.schedule(HacMan::cleanupExpiredRequests, CANCEL_HAC_MAN_AFTER_MS, TimeUnit.MILLISECONDS);
    }

    @Parameter(names = {"--username", "-u"}, order = 0, description = "<Hac username>, default 'admin'")
    private String username;

    @Parameter(names = {"--password", "-p"}, order = 1, description = "<HAC password>, default 'nimda'")
    private String password;

    @Parameter(names = {"--commerce", "-c"}, order = 2, description = "<SAP commerce URL>, default https://127.0.0.1:9002")
    private String server;

    @Parameter(required = true, description = "<Groovy-Script Location>, ex. /home/lucy/SomeGroovyHacCommands.txt")
    private String scriptLocation;

    @Parameter(names = "--help", order = 99, help = true, description = "This help message")
    private boolean help;

    /**
     * Run the Hacman.
     */
    public Optional<String> run(final String... arguments) {

        initCmdLineArgs(arguments);

        Optional<String> scriptContent = readScriptFile(getScriptLocation());

        if (scriptContent.isEmpty()) {
            LOG.error("Provided script file {} is empty.", getScriptLocation());
            return Optional.empty();
        }

        return runImpl(getLoginPageUrl(),
                       getPostLoginFormUrl(),
                       getScriptingConsoleUrl(),
                       getUsername(),
                       getPassword(),
                       scriptContent.get());
    }

    /**
     * Run tings:
     *
     * 1) go to login page => csrf token
     * 2) login => new csrf token
     * 3) execute script on the provided HAC endpoint => script output
     */
    private Optional<String> runImpl(final String loginPageUrl,
                                     final String postFormUrl,
                                     final String scriptingConsoleUrl,
                                     final String username,
                                     final String password,
                                     final String script) {

        try (CloseableHttpClient httpclient = createAcceptSelfSignedCertificateClient()) {

            // session cookie storage
            HttpClientContext httpContext = HttpClientContext.create();
            httpContext.setAttribute(HttpClientContext.COOKIE_STORE, new BasicCookieStore());

            // fetch initial csrf token
            Optional<String> initialToken = openLoginPageAndGetToken(loginPageUrl, httpclient, httpContext);

            if (initialToken.isEmpty()) {
                LOG.error("Couldn't obtain csrf token from {}", loginPageUrl);
                return Optional.empty();
            }

            // login and fetch final csrf token
            Optional<String> loginToken = loginAndPostCredentials(postFormUrl,
                                                                  username,
                                                                  password,
                                                                  httpclient,
                                                                  httpContext,
                                                                  initialToken.get());

            if (loginToken.isEmpty()) {
                LOG.error("Couldn't obtain a login csrf token from {}", postFormUrl);
                return Optional.empty();
            }

            // execute script content on remote server
            return executeScript(scriptingConsoleUrl,
                                 loginToken.get(),
                                 httpContext,
                                 httpclient,
                                 script);

        } catch (IOException | ParseException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            LOG.error("Error executing script: {}", getScriptLocation(), e);
            System.exit(ERROR);
        }

        return Optional.empty();
    }

    private Optional<String> openLoginPageAndGetToken(final String loginPageUrl,
                                                      final CloseableHttpClient httpClient,
                                                      final HttpClientContext httpContext)
        throws IOException, ParseException {

        HttpGet httpget = null;

        try {
            httpget = new HttpGet(loginPageUrl);

            RequestConfig requestConfig =
                RequestConfig.custom()
                             .setConnectionRequestTimeout(CONNECTION_TIMEOUT_MS)
                             .setConnectTimeout(CONNECTION_TIMEOUT_MS)
                             .build();

            httpget.setConfig(requestConfig);

            addToRequestMonitor(httpget);

            CloseableHttpResponse response = httpClient.execute(httpget, httpContext);

            LOG.info("Got http status {} from: {}", response.getCode(), loginPageUrl); // NOSONAR

            String body = EntityUtils.toString(response.getEntity());

            LOG.debug("HAC body: {}", body); // NOSONAR

            Document doc = Jsoup.parse(body);
            Elements metaTag = doc.select(META_NAME_CSRF);

            final List<Cookie> cookies = httpContext.getCookieStore().getCookies();

            LOG.debug("Cookie: {} | CSRF: {}",
                      formatCookie(cookies), // NOSONAR
                      getCsrfToken(metaTag));

            return getCsrfToken(metaTag);

        } finally {
            removeFromRequestMonitor(httpget);
        }
    }

    private Optional<String> loginAndPostCredentials(final String postLoginFormUrl,
                                                     final String username,
                                                     final String password,
                                                     final CloseableHttpClient httpClient,
                                                     final HttpClientContext httpContext,
                                                     final String csrfToken)
        throws IOException, ParseException {
        List<NameValuePair> urlParameters;

        HttpPost post = null;

        try {
            final List<Cookie> cookies = httpContext.getCookieStore().getCookies();

            post = new HttpPost(postLoginFormUrl);

            RequestConfig requestConfig =
                RequestConfig.custom()
                             .setConnectionRequestTimeout(CONNECTION_TIMEOUT_MS)
                             .setConnectTimeout(CONNECTION_TIMEOUT_MS)
                             .build();

            post.setConfig(requestConfig);

            addToRequestMonitor(post);

            post.setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0");
            post.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
            post.setHeader("Accept-Language", "en-US,en;q=0.5");
            post.setHeader("Accept-Encoding", "gzip, deflate, br");
            post.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            post.setHeader("Origin", getCommerceBaseUrl());
            post.setHeader("DNT", "1");
            post.setHeader("Connection", "keep-alive");
            post.setHeader("Referer", getLoginPageUrl());
            post.setHeader("Cookie", formatCookie(cookies));
            post.setHeader("Upgrade-Insecure-Requests", "1");
            post.setHeader("Sec-Fetch-Dest", "document");
            post.setHeader("Sec-Fetch-Mode", "navigate");
            post.setHeader("Sec-Fetch-Site", "same-origin");
            post.setHeader("Sec-Fetch-User", "?1");

            // add request parameters or form parameters
            urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("j_username", username));
            urlParameters.add(new BasicNameValuePair("j_password", password));
            urlParameters.add(new BasicNameValuePair("_csrf", csrfToken));

            post.setEntity(new UrlEncodedFormEntity(urlParameters));

            CloseableHttpResponse response = httpClient.execute(post, httpContext);

            LOG.info("Got http status {} from: {}", response.getCode(), postLoginFormUrl);

            String body = EntityUtils.toString(response.getEntity());

            LOG.debug("LOGIN body: {}", body); // NOSONAR

            Document doc = Jsoup.parse(body);
            Elements metaTag = doc.select(META_NAME_CSRF);

            LOG.debug("Cookie: {} | CSRF: {}",
                      formatCookie(cookies), // NOSONAR
                      getCsrfToken(metaTag));

            return getCsrfToken(metaTag);

        } finally {
            removeFromRequestMonitor(post);
        }
    }

    private Optional<String> executeScript(final String scriptingConsoleUrl,
                                           final String csrfToken,
                                           final HttpClientContext httpContext,
                                           final CloseableHttpClient httpclient,
                                           final String script)
        throws IOException, ParseException {

        HttpPost post = null;

        try {
            final List<Cookie> cookies = httpContext.getCookieStore().getCookies();

            post = new HttpPost(scriptingConsoleUrl);

            RequestConfig requestConfig =
                RequestConfig.custom()
                             .setConnectionRequestTimeout(CONNECTION_TIMEOUT_MS)
                             .setConnectTimeout(CONNECTION_TIMEOUT_MS)
                             .build();

            post.setConfig(requestConfig);

            addToRequestMonitor(post);

            post.setHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0");
            post.setHeader("X-CSRF-TOKEN", csrfToken);
            post.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            post.setHeader("Accept", "application/json");
            post.setHeader("Accept-Language", "en-US,en;q=0.5");
            post.setHeader("Accept-Encoding", "gzip, deflate, br");
            post.setHeader("X-Requested-With", "XMLHttpRequest");
            post.setHeader("Origin", getCommerceBaseUrl());
            post.setHeader("DNT", "1");
            post.setHeader("Connection", "keep-alive");
            post.setHeader("Referer", getScriptingConsoleUrl());
            post.setHeader("Sec-Fetch-Dest", "empty");
            post.setHeader("Sec-Fetch-Mode", "cors");
            post.setHeader("Sec-Fetch-Site", "same-origin");
            post.setHeader("Cookie", formatCookie(cookies));

            List<NameValuePair> urlParameters;

            urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("scriptType", "groovy"));
            urlParameters.add(new BasicNameValuePair("commit", "false"));
            urlParameters.add(new BasicNameValuePair("script", script));
            post.setEntity(new UrlEncodedFormEntity(urlParameters));

            CloseableHttpResponse response = httpclient.execute(post, httpContext);

            LOG.info("Got http status {} from: {}", response.getCode(), scriptingConsoleUrl);

            final String body = EntityUtils.toString(response.getEntity());

            LOG.debug("EXE body: {}", body); // NOSONAR

            final String result = StringUtils.substringBetween(body,
                                                               "\"executionResult\":\"",
                                                               "\",\"outputText\"");

            return Optional.of(
                StringUtils.defaultString(
                    StringUtils.trimToNull(result), VOID_SCRIPT_RESULT)
            );

        } finally {
            removeFromRequestMonitor(post);
        }
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

    /**
     * @see "https://jcommander.org/#_overview"
     */
    private void initCmdLineArgs(final String... arguments) {

        try {
            final JCommander jCommander =
                JCommander.newBuilder()
                          .addObject(this)
                          .build();

            jCommander.setProgramName("java -jar hacman.jar");

            jCommander.parse(arguments);

            if (getHelp()) {
                jCommander.usage();
                System.exit(OK);
            }

            LOG.debug("User: {}", getUsername());
            LOG.debug("Password: {}", getPassword());
            LOG.debug("Commerce: {}", getCommerceBaseUrl());
            LOG.debug("Script: {}", getScriptLocation());
        } catch (ParameterException e) {
            LOG.error("Missing or invalid program argument:", e);
            System.exit(ERROR);
        }
    }

    private Optional<String> readScriptFile(final String scriptLocation) {

        if (StringUtils.isEmpty(scriptLocation)) {
            LOG.error("ScriptLocation is missing!");
            return Optional.empty();
        }

        try {
            File file = new File(scriptLocation);
            return Optional.of(FileUtils.readFileToString(file, StandardCharsets.UTF_8));
        } catch (IOException e) {
            LOG.error("Error reading script from: {}", scriptLocation, e);
        }

        return Optional.empty();
    }

    private static void cleanupExpiredRequests() {
        long now = System.currentTimeMillis();
        // find expired requests
        List<HttpUriRequestBase> expiredRequests =
            REQUEST_MONITOR.entrySet().stream()
                           .filter(dueTime -> dueTime.getValue() > now)
                           .map(Map.Entry::getKey)
                           .collect(Collectors.toList());

        // cancel requests
        expiredRequests.forEach(r -> {
            if (!r.isCancelled()) {
                LOG.error("Cancelled request {} after {} ms", r.getRequestUri(), CANCEL_HAC_MAN_AFTER_MS);
                r.cancel();
            }
            REQUEST_MONITOR.remove(r);
        });

        if (!expiredRequests.isEmpty()) {
            System.exit(ERROR);
        }
    }

    public static void addToRequestMonitor(HttpUriRequestBase request) {
        REQUEST_MONITOR.put(request, System.currentTimeMillis() + CANCEL_HAC_MAN_AFTER_MS);
    }

    public static void removeFromRequestMonitor(HttpUriRequestBase request) {
        REQUEST_MONITOR.remove(request);
    }

    private Optional<String> getCsrfToken(final Elements metaTag) {
        return metaTag.first() != null ?
               Optional.ofNullable(StringUtils.trimToNull(metaTag.first().attr(META_CONTENT))) :
               Optional.empty();
    }

    private String getCommerceBaseUrl() {
        return StringUtils.defaultString(server, HTTPS_127_0_0_1_9002);
    }

    private String getLoginPageUrl() {
        return MessageFormat.format(URL_PATH_PATTERN, getCommerceBaseUrl(), HAC_LOGIN);
    }

    private String getPostLoginFormUrl() {
        return MessageFormat.format(URL_PATH_PATTERN, getCommerceBaseUrl(), HAC_J_SPRING_SECURITY_CHECK);
    }

    private String getScriptingConsoleUrl() {
        return MessageFormat.format(URL_PATH_PATTERN, getCommerceBaseUrl(), HAC_CONSOLE_SCRIPTING_EXECUTE);
    }

    private String getUsername() {
        return StringUtils.defaultString(username, ADMIN);
    }

    private String getPassword() {
        return StringUtils.defaultString(password, ADMIN_PWD);
    }

    private String getScriptLocation() {
        return StringUtils.defaultString(scriptLocation, "");
    }

    private boolean getHelp() {
        return this.help;
    }

    private String formatCookie(final List<Cookie> cookies) {
        return cookies.stream().map(this::formatCookie).collect(Collectors.joining("; "));
    }

    private String formatCookie(Cookie cookie) {
        return MessageFormat.format("{0}={1}", cookie.getName(), cookie.getValue());
    }
}
