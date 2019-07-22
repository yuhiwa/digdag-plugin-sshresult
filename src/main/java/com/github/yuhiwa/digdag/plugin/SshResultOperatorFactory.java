package com.github.yuhiwa.digdag.plugin;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.common.base.Optional;
import com.google.common.base.Throwables;

import io.digdag.client.config.Config;
import io.digdag.client.config.ConfigException;
import io.digdag.client.config.ConfigFactory;
import io.digdag.spi.Operator;
import io.digdag.spi.OperatorContext;
import io.digdag.spi.OperatorFactory;
import io.digdag.spi.SecretProvider;
import io.digdag.spi.TaskResult;
import io.digdag.spi.TemplateEngine;
import io.digdag.util.BaseOperator;
import io.digdag.util.RetryExecutor;
import io.digdag.spi.PrivilegedVariables;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static io.digdag.util.RetryExecutor.retryExecutor;

public class SshResultOperatorFactory
        implements OperatorFactory
{
    @SuppressWarnings("unused")
    private final TemplateEngine templateEngine;

    private static Logger logger = LoggerFactory.getLogger(SshResultOperatorFactory.class);

    private static final int RETRY_NUM = 10;
    private static final int RETRY_INTERVAL = 5;
    private static Pattern VALID_ENV_KEY = Pattern.compile("[a-zA-Z_][a-zA-Z_0-9]*");

    public SshResultOperatorFactory(TemplateEngine templateEngine)
    {
        this.templateEngine = templateEngine;
    }

    public String getType()
    {
        return "ssh_result";
    }

    @Override
    public Operator newOperator(OperatorContext context)
    {
        return new SshResultOperator(context);
    }

    private class SshResultOperator
            extends BaseOperator
    {
        public SshResultOperator(OperatorContext context)
        {
            super(context);
        }

        private final int defaultCommandTimeout = 60;
        private final static int defaultInitialRetryWait = 500;
        private final static int defaultMaxRetryWait = 2000;
        private final static int defaultMaxRetryLimit = 3;
        Session session;
        ChannelExec channel;
        Config storeParams;

        @Override
        public TaskResult runTask()
        {
            Config params = request.getConfig().mergeDefault(
                    request.getConfig().getNestedOrGetEmpty("ssh_result"));

            String command = params.get("_command", String.class);
            String host = params.get("host", String.class);
            int port = params.get("port", int.class, 22);
            int cmd_timeout = params.get("command_timeout", int.class, defaultCommandTimeout);
            long cmd_timeout_msec = cmd_timeout * 1000;
            int initial_retry_wait = params.get("initial_retry_wait", int.class, defaultInitialRetryWait);
            int max_retry_wait = params.get("max_retry_wait", int.class, defaultMaxRetryWait);
            int max_retry_limit = params.get("max_retry_limit", int.class, defaultMaxRetryLimit);

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(workspace.getPath().toFile());

            final Map<String, String> env = pb.environment();

            params.getKeys()
                .forEach(key -> {
                  if (isValidEnvKey(key)) {
                    JsonNode value = params.get(key, JsonNode.class);
                    String string;
                    if (value.isTextual()) {
                      string = value.textValue();
                    } else {
                      string = value.toString();
                    }
                    env.put(key, string);
                  } else {
                    logger.trace("Ignoring invalid env var key: {}", key);
                  }
                });

            // Set up process environment according to env config. This can also refer to secrets.
            collectEnvironmentVariables(env, context.getPrivilegedVariables());

            try {
                logger.info(String.format("Connecting %s:%d", host, port));

                RetryExecutor retryExecutor = retryExecutor()
                        .retryIf(exception -> true)
                        .withInitialRetryWait(initial_retry_wait)
                        .withMaxRetryWait(max_retry_wait)
                        .onRetry( (exception, retryCount, retryLimit, retryWait) -> logger.warn(
                                "Connection failed: retry {} of {} (wait {}ms)", retryCount, retryLimit, retryWait, exception))
                        .withRetryLimit(max_retry_limit);


                try {
                      retryExecutor.run(() -> {
                        try {
                            JSch sshTmp = new JSch();
                            authorize(sshTmp);
                            session.connect();
                            return sshTmp;
                        }
                        catch (Exception e) {
                            throw Throwables.propagate(e);
                        }
                    });
                }
                catch (RetryExecutor.RetryGiveupException ex) {
                    throw Throwables.propagate(ex.getCause());
                }

                try {
                    logger.info(String.format("Execute command: %s", command));
                    channel = (ChannelExec) session.openChannel("exec");
                    channel.setCommand(command);
                    channel.setInputStream(null);
                    StringBuilder outputBuffer = new StringBuilder();
                    StringBuilder errorBuffer = new StringBuilder();
                    InputStream stdout = channel.getInputStream();
                    InputStream stderr = channel.getErrStream();
                    channel.connect();

                    byte[] tmp = new byte[1024];
                    long start = System.currentTimeMillis();
                    while (true) {
                        while (stdout.available() > 0) {
                            int i = stdout.read(tmp, 0, 1024);
                            if (i < 0) { break; }
                            outputBuffer.append(new String(tmp, 0, i));
                        }
                        while (stderr.available() > 0) {
                            int i = stderr.read(tmp, 0, 1024);
                            if (i < 0) { break; }
                            errorBuffer.append(new String(tmp, 0, i));
                        }
                        if (channel.isClosed()) {
                            if ((stdout.available() > 0) || (stderr.available() > 0)) { continue; }
                            System.out.println("exit-status: " + channel.getExitStatus());
                            break;
                        }
                        if ((System.currentTimeMillis() - start) > cmd_timeout_msec) {
                            logger.error(String.format("Command timeout (exceeded %d seconds)", cmd_timeout));
                            break;
                        }
                        try {
                            Thread.sleep(1000);
                        }
                        catch (Exception ee) {
                        }
                    }

                    // prepare keep stdout
                    String stdoutData = outputBuffer.toString();
                    String varName = params.get("destination_variable", String.class);
                    String stdoutFormat = params.get("stdout_format", String.class);
                    ConfigFactory cf = request.getConfig().getFactory();

                    // dump stdout and stderr
                    String stderrData = errorBuffer.toString();
                    boolean stdout_log = params.get("stdout_log", boolean.class, true);
                    if (stdout_log) {
                        logger.info("STDOUT output");
                        outputResultLog(stdoutData);
                    }

                    boolean stderr_log = params.get("stderr_log", boolean.class, false);
                    if (stderr_log) {
                        logger.info("STDERR output");
                        outputResultLog(stderrData);
                    }

                    // keep stdout
                    storeParams = cf.create();
                    storeParams.set(varName, createVariableObjectFromStdout(stdoutData, stdoutFormat));
                }
                catch (Exception e) {
                    throw Throwables.propagate(e);
                }
                finally {
                    if (channel != null && channel.isConnected()) {
                        // ssh.close();
                        channel.disconnect();
                    }
                    int status = channel.getExitStatus();
                    logger.info("Status: " + status);
                    if (status != 0) {
                        throw new RuntimeException(String.format("Command failed with code %d", status));
                    }
                    if (session != null && session.isConnected()) {
                        session.disconnect();
                    }
                }
            }
            catch (Exception ex) {
                throw Throwables.propagate(ex);
            }
            return TaskResult.defaultBuilder(request)
                    .storeParams(storeParams)
                    .build();
        }

        private void authorize(JSch ssh)
        {
            Config params = request.getConfig().mergeDefault(request.getConfig().getNestedOrGetEmpty("ssh"));

            String user = params.get("user", String.class);
            String host = params.get("host", String.class);
            int port = params.get("port", int.class, 22);
            SecretProvider secrets = context.getSecrets().getSecrets("ssh");

            try {

                session = ssh.getSession(user, host, port);
                setupHostKeyVerifier(session);

                if (params.get("password_auth", Boolean.class, false)) {
                    Optional<String> password = getPassword(secrets, params);
                    if (!password.isPresent()) {
                        throw new RuntimeException("password not set");
                    }
                    logger.info(String.format("Authenticate user %s with password", user));
                    session.setPassword(password.get());
                }
                else {
                    Optional<String> publicKey = secrets.getSecretOptional("public_key");
                    Optional<String> privateKey = secrets.getSecretOptional("private_key");
                    Optional<String> publicKeyPass = secrets.getSecretOptional("public_key_passphrase");
                    if (!publicKey.isPresent()) {
                        throw new RuntimeException("public_key not set");
                    }
                    if (publicKeyPass.isPresent()) {
                        throw new ConfigException("public_key_passphrase doesn't support yet");
                    }
                    if (!privateKey.isPresent()) {
                        throw new ConfigException("private key not set");
                    }

                    logger.info(String.format("start add Identity"));
                    String id_name = "public_auth";
                    byte[] passphrase = null;
                    ssh.addIdentity(id_name, privateKey.get().getBytes(), publicKey.get().getBytes(), passphrase);

                    logger.info(String.format("Authenticate user %s with public key", user));
                }
            }
            catch (JSchException ex) {
                throw Throwables.propagate(ex);
            }
        }

        private Optional<String> getPassword(SecretProvider secrets, Config params)
        {
            Optional<String> passwordOverrideKey = params.getOptional("password_override", String.class);
            if (passwordOverrideKey.isPresent()) {
                return Optional.of(secrets.getSecret(passwordOverrideKey.get()));
            }
            else {
                return secrets.getSecretOptional("password");
            }
        }

        private void setupHostKeyVerifier(Session session)
        {
/*
            try {
                ssh.loadKnownHosts();
*/
            session.setConfig("StrictHostKeyChecking", "no");
/*
            }
            catch (IOException ex) {
                throw Throwables.propagate(ex);
            }
*/
        }

        private void outputResultLog(String log)
        {
            for(String msg: log.split("\r?\n")){
                logger.info("  " + msg);
            }
        }

        public void collectEnvironmentVariables(Map<String, String> env,
            PrivilegedVariables variables) {
          for (String name : variables.getKeys()) {
            if (!VALID_ENV_KEY.matcher(name).matches()) {
              throw new ConfigException("Invalid _env key name: " + name);
            }
            env.put(name, variables.get(name));
          }
        }

        public Object createVariableObjectFromStdout(String stdoutData, String stdoutFormat) {
            // stdout is text
            if ("text".equals(stdoutFormat)) {
                return stdoutData;
            }

            // case of '*-delimited'
            String delimiter = null;
            if ("newline-delimited".equals(stdoutFormat)) {
                delimiter = "\n";
            } else if ("space-delimited".equals(stdoutFormat)) {
                delimiter = "\n| ";
            }
            if (delimiter != null) {
                List<String> listObj = new LinkedList<>();
                for (String s : stdoutData.split(delimiter)) {
                    if (s.trim().length() > 0) {
                        listObj.add(s.trim());
                    }
                }
                return listObj;
            }

            if ("json-list-map".equals(stdoutFormat)) {
                // stdout is json format
                List<Map<String, Object>> jsonObj;
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    jsonObj = mapper
                        .readValue(stdoutData, new TypeReference<ArrayList<HashMap<String, Object>>>() {
                        });
                } catch (Exception e) {
                    throw Throwables.propagate(e);
                }
                return jsonObj;

            }
            return null;
        }

        private boolean isValidEnvKey(String key) {
            return VALID_ENV_KEY.matcher(key).matches();
        }

    }
}

