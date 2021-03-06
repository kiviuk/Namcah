package de.mobe.namcah;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
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
import org.apache.hc.client5.http.impl.cookie.BasicClientCookie;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.Header;
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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
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

import static de.mobe.namcah.Main.ERR;
import static de.mobe.namcah.Main.HAC_MAN_ERROR;
import static de.mobe.namcah.Main.OK;

public class Namcah {

    private static final Logger LOG = LoggerFactory.getLogger(Namcah.class);
    private static final String META_CONTENT = "content";
    private static final String META_NAME_CSRF = "meta[name='_csrf']";
    private static final String HAC_LOGIN = "hac/login";
    private static final String HAC_J_SPRING_SECURITY_CHECK = "hac/j_spring_security_check";
    private static final String HAC_CONSOLE_SCRIPTING_EXECUTE = "hac/console/scripting/execute";
    private static final String URL_PATH_PATTERN = "{0}/{1}";
    private static final String ADMIN = "admin";
    private static final String ADMIN_PWD = StringUtils.reverse(ADMIN);
    private static final String HTTPS_127_0_0_1_9002 = "https://127.0.0.1:9002";
    private static final int MAX_LOGIN_ATTEMPTS = 100;
    private static final Timeout CONNECTION_TIMEOUT_MS = Timeout.of(MAX_LOGIN_ATTEMPTS, TimeUnit.SECONDS);
    private static final long CANCEL_HAC_MAN_AFTER_MS = 60L * 1000 * 100;
    private static final Map<HttpUriRequestBase, Long> REQUEST_MONITOR = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService SCHEDULER = Executors.newScheduledThreadPool(1);


    public static final String VOID_SCRIPT_RESULT = "Command created no output.";

    static {
        SCHEDULER.schedule(Namcah::cleanupExpiredRequests, CANCEL_HAC_MAN_AFTER_MS, TimeUnit.MILLISECONDS);
    }

    @Parameter(names = {"--username", "-u"}, order = 0, description = "<Hac username>, default 'admin'")
    private String username;

    @Parameter(names = {"--password", "-p"}, order = 1, description = "<HAC password>, default 'nimda'")
    private String password;

    @Parameter(names = {"--commerce", "-c"}, order = 2, description = "<SAP commerce URL>, default https://127.0.0.1:9002")
    private String server;

    @Parameter(names = {"--commit", "-t"}, order = 3, description = "Controls the HAC commit mode")
    private boolean commit = false;

    @Parameter(names = {"--route", "-r"}, order = 4, description = "The node route in case of a background processing node")
    private String route;

    @Parameter(names = {"--script", "-s"}, order = 5, description = "Location of the groovy script")
    private String scriptLocation;

    @Parameter(names = {"--debug", "-d"}, order = 98, description = "Enable debug level, (logs are kept in namcah.log)")
    private Boolean debug = false;

    @Parameter(names = {"--help", "-h"}, order = 99, help = true, description = "This help")
    private boolean help;

    /**
     * Go Hacman, go!
     */
    public Optional<String> runHac(final String... arguments) {

        initCmdLineArgs(arguments);

        Optional<String> scriptContent;
        if (StringUtils.isEmpty(getScriptLocation())) {
            scriptContent = readFromPipe();
        } else {
            scriptContent = readScriptFile(getScriptLocation());
        }

        if (scriptContent.isEmpty()) {
            String msg = MessageFormat.format(HAC_MAN_ERROR +
                                                  " reading script file {0}. See log file.",
                                              getScriptLocation());
            LOG.error(msg);
            return Optional.of(msg);
        }

        return runHacImpl(getLoginPageUrl(),
                          getPostLoginFormUrl(),
                          getScriptingConsoleUrl(),
                          getUsername(),
                          getPassword(),
                          scriptContent.get());
    }

    /**
     * 1) visit Hac login page => grep csrf token
     * 2) post login creds => grep new csrf token
     * 3) send script into Hac console => grep script output
     */
    private Optional<String> runHacImpl(final String loginPageUrl,
                                        final String postFormUrl,
                                        final String scriptingConsoleUrl,
                                        final String username,
                                        final String password,
                                        final String script) {

        try (CloseableHttpClient httpClient = createAcceptSelfSignedCertificateClient()) {

            // setup session cookie storage
            HttpClientContext httpContext = HttpClientContext.create();
            httpContext.setAttribute(HttpClientContext.COOKIE_STORE, new BasicCookieStore());

            // grep initial csrf token
            final Optional<String> initialToken =
                shouldConnectToRoute() ?
                openLoginPageAndGrepToken(loginPageUrl, httpClient, httpContext, getRoute()) :
                openLoginPageAndGrepToken(loginPageUrl, httpClient, httpContext);

            if (initialToken.isEmpty()) {
                LOG.error("Couldn't obtain csrf token from {}", loginPageUrl);
                return Optional.empty();
            }

            // login and grep final csrf token
            Optional<String> loginToken = loginWithCredentials(postFormUrl,
                                                               username,
                                                               password,
                                                               httpClient,
                                                               httpContext,
                                                               initialToken.get());

            if (loginToken.isEmpty()) {
                LOG.error("Couldn't obtain a login csrf token from {}", postFormUrl);
                return Optional.empty();
            }

            if (initialToken.get().equals(loginToken.get())) {
                LOG.warn("Login csrf token == initial token {}", initialToken);
            }

            // exec script content on remote server
            return executeScript(scriptingConsoleUrl,
                                 loginToken.get(),
                                 httpContext,
                                 httpClient,
                                 script);

        } catch (IOException
                 | ParseException
                 | NoSuchAlgorithmException
                 | KeyStoreException
                 | KeyManagementException e) {

            String msg = MessageFormat.format(HAC_MAN_ERROR + " executing script: {0}",
                                              getScriptLocation());
            LOG.error(msg, getScriptLocation(), e);

            return Optional.of(msg);

        } finally {
            forcedCleanupExpiredRequests();
        }
    }

    private Optional<String> openLoginPageAndGrepToken(final String loginPageUrl,
                                                       final CloseableHttpClient httpClient,
                                                       final HttpClientContext httpContext)
        throws IOException, ParseException {

        return openLoginPageAndGrepTokenInternal(loginPageUrl, httpClient, httpContext);

    }

    private Optional<String> openLoginPageAndGrepToken(final String loginPageUrl,
                                                       final CloseableHttpClient httpClient,
                                                       final HttpClientContext httpContext,
                                                       final String requestedRoute)
        throws IOException, ParseException {

        int attempt = 0;
        boolean foundRequestedRoute;
        Cookie routeCookie;
        Optional<String> optCsrf;

        do {

            httpContext.getCookieStore().clear();

            optCsrf = openLoginPageAndGrepTokenInternal(loginPageUrl, httpClient, httpContext);

            final List<Cookie> cookies = httpContext.getCookieStore().getCookies();

            routeCookie = getRouteCookie(cookies);

            attempt++;

            LOG.debug("Attempt {}/{} to connect to requested route '{}'",
                      attempt,
                      MAX_LOGIN_ATTEMPTS,
                      requestedRoute);

            foundRequestedRoute = routeCookie.getValue().endsWith(requestedRoute);

            if (!foundRequestedRoute && attempt == MAX_LOGIN_ATTEMPTS) {
                LOG.info("Route '{}' not found. Using '{}'", getRoute(), routeCookie.getValue());
            }

        } while (!foundRequestedRoute && attempt < MAX_LOGIN_ATTEMPTS);

        final String routeFoundMessage =
            MessageFormat.format("Connected to requested route: {0} after {1} attempts.",
                                 formatCookie(routeCookie),
                                 attempt);

        System.err.println(routeFoundMessage); // NOSONAR

        LOG.info(routeFoundMessage);

        return optCsrf;
    }

    private Optional<String> openLoginPageAndGrepTokenInternal(final String loginPageUrl,
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

            LOG.debug("Cookie: {}",
                      formatCookies(cookies)); // NOSONAR
            LOG.debug("CSRF: {}",
                      grepCsrfToken(metaTag).orElse("void")); // NOSONAR

            LOG.info("DOMAIN {}", getSessionCookie(cookies).getDomain());

            return grepCsrfToken(metaTag);

        } finally {
            removeFromRequestMonitor(httpget);
        }
    }

    private Optional<String> loginWithCredentials(final String postLoginFormUrl,
                                                  final String username,
                                                  final String password,
                                                  final CloseableHttpClient httpClient,
                                                  final HttpClientContext httpContext,
                                                  final String csrfToken)
        throws IOException, ParseException {

        HttpPost post = null;

        try {

            final List<Cookie> cookies = httpContext.getCookieStore().getCookies();

            for (Cookie cookie : cookies) {
                LOG.debug("Cookie {}: {}", cookie.getName(), cookie.getValue());
            }

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
            post.setHeader("Referer", getCommerceBaseUrl() + "/backoffice/login.zul");
            post.setHeader("Cookie", formatCookies(cookies));
            post.setHeader("Upgrade-Insecure-Requests", "1");
            post.setHeader("Sec-Fetch-Dest", "document");
            post.setHeader("Sec-Fetch-Mode", "navigate");
            post.setHeader("Sec-Fetch-Site", "same-origin");
            post.setHeader("Sec-Fetch-User", "?1");

            LOG.debug("loginWithCredentials headers");
            for (Header header : post.getHeaders()) {
                LOG.debug("{}: {}", header.getName(), header.getValue());
            }

            // add request parameters or form parameters
            List<NameValuePair> urlParameters;
            urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("j_username", username));
            urlParameters.add(new BasicNameValuePair("j_password", password));
            urlParameters.add(new BasicNameValuePair("_csrf", csrfToken));

            for (NameValuePair urlParameter : urlParameters) {
                LOG.debug("{}: {}", urlParameter.getName(), urlParameter.getValue());
            }

            post.setEntity(new UrlEncodedFormEntity(urlParameters));

            LOG.debug("post.getEntity().toString() = " + post.getEntity()); // NOSONAR

            CloseableHttpResponse response = httpClient.execute(post, httpContext);

            LOG.info("Got http status {} from: {}", response.getCode(), postLoginFormUrl);

            String body = EntityUtils.toString(response.getEntity());

            LOG.debug("LOGIN body: {}", body); // NOSONAR

            Document doc = Jsoup.parse(body);
            Elements metaTag = doc.select(META_NAME_CSRF);

            LOG.debug("Cookie: {}",
                      formatCookies(cookies)); // NOSONAR
            LOG.debug("CSRF: {}",
                      grepCsrfToken(metaTag).orElse("void")); // NOSONAR

            return grepCsrfToken(metaTag);

        } finally {
            removeFromRequestMonitor(post);
        }
    }

    private Optional<String> executeScript(final String scriptingConsoleUrl,
                                           final String csrfToken,
                                           final HttpClientContext httpContext,
                                           final CloseableHttpClient httpClient,
                                           final String script)
        throws IOException, ParseException {

        System.err.println( "Executing script: "+ script); // NOSONAR

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
            post.setHeader("Cookie", formatCookies(cookies));

            List<NameValuePair> urlParameters;

            urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("scriptType", "groovy"));
            urlParameters.add(new BasicNameValuePair("commit", String.valueOf(isCommitEnabled())));
            urlParameters.add(new BasicNameValuePair("script", script));
            post.setEntity(new UrlEncodedFormEntity(urlParameters));

            CloseableHttpResponse response = httpClient.execute(post, httpContext);

            LOG.info("Got http status {} from: {}", response.getCode(), scriptingConsoleUrl);

            final String body = EntityUtils.toString(response.getEntity());

            LOG.debug("Script execution result body: {}", body); // NOSONAR

            return Optional.of(formatScriptResult(body, cookies));

        } finally {
            removeFromRequestMonitor(post);
        }
    }

    private String formatScriptResult(final String body, final List<Cookie> cookies) {
        final String scriptResult =
            StringUtils
                .substringBetween(body, "\"executionResult\":\"", "\",\"outputText\"")
                .replace("\\n", "\n")
                .trim();

        final String scriptResultOrDefault =
            StringUtils.defaultString(
                StringUtils.trimToNull(scriptResult), VOID_SCRIPT_RESULT
            );

        final String metaInfo =
            MessageFormat.format("Commerce: {0}\nRoute: {1}\nScript: {2}",
                                 getCommerceBaseUrl(),
                                 shouldConnectToRoute() ? getRouteCookie(cookies).getValue() : "main",
                                 getScriptLocation()
                         )
                         .trim();

        String scriptResultWrapped =
            MessageFormat.format("<namcah>{0}{1}{2}</namcah>",
                                 System.lineSeparator(),
                                 scriptResultOrDefault,
                                 System.lineSeparator());

        System.err.println(metaInfo); // NOSONAR

        return scriptResultWrapped;
    }

    private Optional<String> readFromPipe() {

        List<String> scriptLines = new ArrayList<>();

        try (InputStreamReader isReader = new InputStreamReader(System.in);
             BufferedReader bufReader = new BufferedReader(isReader);) {

            String inputStr = "";
            while (inputStr != null) {
                inputStr = bufReader.readLine();
                if (inputStr != null) {
                    scriptLines.add(inputStr);
                } else {
                    //  System.err.println("inputStr is null"); // NOSONAR
                }
            }
        } catch (IOException e) {
            System.err.println(e.getMessage()); // NOSONAR
        }

        return Optional.ofNullable(StringUtils.trimToNull(String.join(System.lineSeparator(), scriptLines)));
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

    private Optional<String> readScriptFile(final String scriptLocation) {

        if (StringUtils.isEmpty(scriptLocation)) {
            LOG.error("ScriptLocation is missing!");
            return Optional.empty();
        }

        try {
            File file = new File(scriptLocation);

            String content =
                StringUtils.trimToNull(FileUtils.readFileToString(file, StandardCharsets.UTF_8));

            return Optional.ofNullable(content);
        } catch (IOException e) {
            LOG.error("Error reading script from: {}", scriptLocation, e);
        }

        return Optional.empty();
    }

    private static void cleanupExpiredRequests() {
        long now = System.currentTimeMillis();
        cleanupExpiredRequestsInternal(now);
    }

    private static void forcedCleanupExpiredRequests() {
        cleanupExpiredRequestsInternal(0L);
    }


    private static void cleanupExpiredRequestsInternal(final long now) {
        // find expired requests
        List<HttpUriRequestBase> expiredRequests =
            REQUEST_MONITOR.entrySet().stream()
                           .filter(dueTime -> dueTime.getValue() > now)
                           .map(Map.Entry::getKey)
                           .collect(Collectors.toList());

        // cancel requests
        expiredRequests.forEach(r -> {
            if (!r.isCancelled()) {
                r.cancel();
                String msg = MessageFormat.format("Cancelled request {0} after {1} ms",
                                                  r.getRequestUri(),
                                                  CANCEL_HAC_MAN_AFTER_MS);
                LOG.error(msg);
                System.out.println(msg); // NOSONAR
            }
            REQUEST_MONITOR.remove(r);
        });

        if (!expiredRequests.isEmpty()) {
            String msg = "Expired request found!";
            System.out.println(msg); // NOSONAR
            System.exit(ERR);
        }
    }

    public static void addToRequestMonitor(final HttpUriRequestBase request) {
        REQUEST_MONITOR.put(request, System.currentTimeMillis() + CANCEL_HAC_MAN_AFTER_MS);
    }

    public static void removeFromRequestMonitor(final HttpUriRequestBase request) {
        if (request != null) {
            REQUEST_MONITOR.remove(request);
        }
    }

    private Optional<String> grepCsrfToken(final Elements metaTag) {
        return metaTag.first() != null ?
               Optional.ofNullable(StringUtils.trimToNull(metaTag.first().attr(META_CONTENT))) :
               Optional.empty();
    }

    private Cookie getRouteCookie(final List<Cookie> cookies) {
        return getCookieImpl(cookies, "ROUTE");
    }

    private Cookie getSessionCookie(final List<Cookie> cookies) {
        return getCookieImpl(cookies, "JSESSIONID");
    }

    private Cookie getCookieImpl(final List<Cookie> cookies, final String cookieId) {
        BasicClientCookie dummyCookie = new BasicClientCookie("DUMMY", "VALUE");

        return cookies.stream()
                      .filter(c -> cookieId.equals(c.getName())).collect(Collectors.toList())
                      .stream().findAny().orElse(dummyCookie);
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

    private String getRoute() {
        return StringUtils.defaultString(route, "");
    }

    private boolean shouldConnectToRoute() {
        return StringUtils.isNotEmpty(getRoute());
    }

    private boolean isDebugEnabled() {
        return debug;
    }

    private boolean getHelp() {
        return help;
    }

    private boolean isCommitEnabled() {
        return this.commit;
    }

    private String formatCookies(final List<Cookie> cookies) {
        return cookies.stream().map(this::formatCookie).collect(Collectors.joining("; "));
    }

    private String formatCookie(final Cookie cookie) {
        return MessageFormat.format("{0}={1}", cookie.getName(), cookie.getValue());
    }

    private void setDebugLogLevel() {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        ch.qos.logback.classic.Logger logger = loggerContext.getLogger(Namcah.class);
        logger.setLevel(Level.toLevel("DEBUG"));
    }

    /**
     * @see "<a href="https://jcommander.org/#_overview">https://jcommander.org/#_overview</a>"
     */
    private void initCmdLineArgs(final String... arguments) {

        final String HELP_TXT_1 =
            "Example 1: \n echo '\"ls -hl /\".execute().text' | java -jar ./target/namcah.jar -c https://localhost:9002 -u admin -p nimda";

        final String HELP_TXT_2 =
            "Example 2: \n java -jar ./target/namcah.jar -s /home/user/scripts/script.txt -c https://localhost:9002 -u admin -p nimda";

        final String HELP_TXT_3 = "Use 'echo $?' to grep the system exit code: 0 = OK, 1 = Error";

        try {
            final JCommander jCommander =
                JCommander.newBuilder()
                          .addObject(this)
                          .build();

            jCommander.setProgramName("java -jar namcah.jar");

            jCommander.parse(arguments);

            if (getHelp()) {
                jCommander.usage();
                System.out.println(HELP_TXT_1); // NOSONAR
               // System.out.println("\n"); // NOSONAR
                System.out.println(HELP_TXT_2); // NOSONAR
                //System.out.println("\n"); // NOSONAR
                System.out.println(HELP_TXT_3); // NOSONAR
                System.exit(OK);
            }

            if (isDebugEnabled()) {
                setDebugLogLevel();
            }

            LOG.debug("User: {}", getUsername());
            LOG.debug("Password: {}", getPassword());
            LOG.debug("Commerce: {}", getCommerceBaseUrl());
            LOG.debug("Script: {}", getScriptLocation());
            LOG.debug("Debug enabled: {}", isDebugEnabled());
            LOG.debug("Commit enabled: {}", isCommitEnabled());

        } catch (ParameterException e) {
            String msg = MessageFormat.format("Missing or invalid program argument: {0}", e);
            LOG.error(msg);
            System.out.println("msg = " + msg); // NOSONAR
            System.exit(ERR);
        }
    }
}
