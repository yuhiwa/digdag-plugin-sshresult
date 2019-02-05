package com.github.yuhiwa.digdag.plugin;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.common.base.Optional;
import com.google.common.base.Throwables;

import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;

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
import io.digdag.spi.PrivilegedVariables;
import io.digdag.spi.TaskExecutionException;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.BaseFileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil;
import net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.time.Duration;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


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

        @Override
        public TaskResult runTask()
        {
            Config params = request.getConfig().mergeDefault(
                    request.getConfig().getNestedOrGetEmpty("ssh"));

            String command = params.get("_command", String.class);
            String host = params.get("host", String.class);
            int port = params.get("port", int.class, 22);
            int cmd_timeo = params.get("command_timeout", int.class, defaultCommandTimeout);

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

            final SSHClient ssh = new SSHClient();

            try {
                try {
                    setupHostKeyVerifier(ssh);

                    logger.info(String.format("Connecting %s:%d", host, port));
                    for (int retryNum = 0; retryNum< RETRY_NUM; retryNum++) {
                        try {
//                            logger.info(retryNum + 1 + "times trying");
                            ssh.connect(host, port);
                            break;
                        } catch (Exception e) {
                            try {
                                TimeUnit.SECONDS.sleep(RETRY_INTERVAL);
                            } catch (InterruptedException e1) {
                                e1.printStackTrace();
                            }
                        } finally {
                        }
                    }

                    try {

                        authorize(ssh);
                        final Session session = ssh.startSession();

                        logger.info(String.format("Execute command: %s", command));
                        final Session.Command result = session.exec(command);
                        result.join(cmd_timeo, TimeUnit.SECONDS);

                        int status = result.getExitStatus();

                        // keep stdout
                        String stdoutData = IOUtils.readFully(result.getInputStream()).toString();

                        String varName = params.get("destination_variable", String.class);
                        String stdoutFormat = params.get("stdout_format", String.class);

                        ConfigFactory cf = request.getConfig().getFactory();
                        Config storeParams = cf.create();

                        storeParams.set(varName, createVariableObjectFromStdout(stdoutData, stdoutFormat));

                        // dump stderr
                        String stderrData = IOUtils.readFully(result.getErrorStream()).toString();

                        boolean stdout_log = params.get("stdout_log",boolean.class,true);
                        if( stdout_log ) {
                            logger.info("STDOUT output");
                            outputResultLog(stdoutData);
                        }

                        boolean stderr_log = params.get("stderr_log",boolean.class,false);
                        if( stderr_log ){
                            logger.info("STDERR output");
                            outputResultLog(stderrData);
                        }

                        logger.info("Status: " + status);
                        if (status != 0) {
                            throw new RuntimeException(String.format("Command failed with code %d", status));
                        }

                        return TaskResult.defaultBuilder(request)
                            .storeParams(storeParams)
                            .build();

                    }
                    catch (ConnectionException ex) {
                        throw Throwables.propagate(ex);
                    }
                    finally {
                        ssh.close();
                    }


                }
                finally {
                    ssh.disconnect();
                }
            } catch ( IOException ex){
                throw Throwables.propagate(ex);
            }
        }

        private void authorize(SSHClient ssh)
        {
            Config params = request.getConfig().mergeDefault(
                    request.getConfig().getNestedOrGetEmpty("ssh"));

            String user = params.get("user", String.class);
            SecretProvider secrets = context.getSecrets().getSecrets("ssh");;

            try {
                if (params.get("password_auth", Boolean.class, false)) {
                    Optional<String> password = getPassword(secrets, params);
                    if (!password.isPresent()) {
                        throw new RuntimeException("password not set");
                    }
                    logger.info(String.format("Authenticate user %s with password", user));
                    ssh.authPassword(user, password.get());
                }
                else {
                    Optional<String> publicKey = secrets.getSecretOptional("public_key");
                    Optional<String> privateKey = secrets.getSecretOptional("private_key");
                    Optional<String> publicKeyPass = secrets.getSecretOptional("public_key_passphrase");
                    if (!publicKey.isPresent()) {
                        throw new RuntimeException("public_key not set");
                    }
                    if (publicKeyPass.isPresent()) {
                        // TODO
                        // ssh.authPublickey(user,publicKey.get());
                        throw new ConfigException("public_key_passphrase doesn't support yet");
                    }
                    if (!privateKey.isPresent()) {
                        throw new ConfigException("private key not set");
                    }

                    OpenSSHKeyFile keyfile = new OpenSSHKeyFile();

                    keyfile.init(privateKey.get(), publicKey.get());
                    logger.info(String.format("Authenticate user %s with public key", user));
                    ssh.authPublickey(user, keyfile);
                }
            }
            catch (UserAuthException | TransportException ex) {
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

        private void setupHostKeyVerifier(SSHClient ssh)
        {
            ssh.addHostKeyVerifier(new PromiscuousVerifier());
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
                } catch (IOException e) {
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

