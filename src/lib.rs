use std::{
    collections::HashMap,
    fmt::Write as FmtWrite,
    fs,
    io::{self, Write},
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use regex::Regex;
use tempfile::TempPath;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UnixListener,
    process::{Child, ChildStderr, Command},
    sync::RwLock,
};
use tracing::{error, info, trace};

/// An RAII holder for the started stunnel process. When this is
/// dropped, we send SIGKILL to stunnel.
pub struct STunnel {
    /// The domain socket listeners, indexed by service name.
    unix_listeners: HashMap<String, UnixListener>,

    /// Any allocated temporary files. Stored here to keep them from
    /// being deleted until this is dropped.
    #[allow(unused)]
    temp_files: Vec<TempPath>,

    /// The stunnel child process.
    #[allow(unused)]
    child: Child,

    /// Synchronization for wait_for_ready. When starting up, we take
    /// a write lock on this, which is released once stunnel reports
    /// that it's ready. wait_for_ready takes a read lock on it, which
    /// so it will block until init is complete.
    initialized: Arc<RwLock<()>>,
}

/// Top-level stunnel configuration structure
pub struct Config {
    pub services: Vec<Service>,
}

/// A single serve in the stunnel configuration
pub struct Service {
    /// The service name. This will be the `[service]` entry in the
    /// generated stunnel config.  The same string is passed to
    /// `take_unix_listener` after start.
    pub name: String,

    /// What host / ip should stunnel listen on? If None, listn on all
    /// IPv4 addresses. Pass "::" to listen on all IPv6 addresses. See
    /// stunnels "accept" entry.
    pub accept_host: Option<String>,

    /// Waht port should stunnel listen on? See stunnels "accept" entry.
    pub accept_port: u16,

    /// The certificate chain file. See stunnel's "cert" entry.
    pub cert: PathBuf,

    /// The private key that goes with 'cert'. See stunnel's "key" entry.
    pub key: PathBuf,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO Error")]
    Io(#[from] std::io::Error),

    #[error("Format Error")]
    Fmt(#[from] std::fmt::Error),
}

/// A small wrapper for config file formatting purposes.
struct ServiceWithSocket<'a, 'b> {
    service: &'a Service,
    socket: &'b Path,
}

impl STunnel {
    /// Start an stunnel process. A domain socket will be created for
    /// each service in the config entry, prefixed with the service
    /// name and suffixed with ".sock".
    pub async fn start(config: Config) -> Result<STunnel, Error> {
        let mut unix_listeners = HashMap::new();
        let mut temp_files = vec![];
        let mut config_file_content = String::new();

        let initialized = Arc::new(RwLock::new(()));

        writeln!(config_file_content, "foreground = yes")?;
        writeln!(config_file_content, "syslog = no")?;
        writeln!(config_file_content, "pid = ")?;
        writeln!(config_file_content)?;

        for service in config.services.into_iter() {
            let (uds_listener, uds_path) = Self::make_uds(&service.name)?;

            write!(
                config_file_content,
                "{}",
                ServiceWithSocket {
                    service: &service,
                    socket: &uds_path
                }
            )?;
            writeln!(config_file_content)?;

            unix_listeners.insert(service.name, uds_listener);
            temp_files.push(uds_path);
        }

        let mut config_file = tempfile::Builder::new()
            .prefix("stunnel_")
            .suffix(".conf")
            .tempfile()?;
        config_file
            .as_file_mut()
            .write_all(config_file_content.as_bytes())?;

        info!(?config_file, "Created stunnel config");
        let mut child = Command::new("stunnel")
            .arg(config_file.as_ref())
            // stunnel prints its logs to stderr
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        info!(pid = child.id(), "Started stunnel");
        temp_files.push(config_file.into_temp_path());

        let stderr = child.stderr.take().unwrap();
        let initialized_for_log_translate = initialized.clone();
        tokio::spawn(translate_stunnel_logs(
            stderr,
            initialized_for_log_translate,
        ));

        Ok(STunnel {
            unix_listeners,
            temp_files,
            child,
            initialized,
        })
    }

    fn make_uds(name: &str) -> io::Result<(UnixListener, TempPath)> {
        let uds_file = tempfile::Builder::new()
            .prefix(&format!("{name}_"))
            .suffix(".sock")
            .tempfile()?;

        let uds_path = uds_file.into_temp_path();

        // remove the file, then remake it as a uds
        fs::remove_file(&uds_path)?;
        info!(?uds_path, "Listening on domain socket");
        let uds_listener = UnixListener::bind(&uds_path)?;

        let mut uds_perms = fs::metadata(&uds_path)?.permissions();
        uds_perms.set_mode(0o700);
        fs::set_permissions(&uds_path, uds_perms)?;

        Ok((uds_listener, uds_path))
    }

    /// Get the listener for one of the started services
    pub fn take_unix_listener(&mut self, service_name: &str) -> Option<UnixListener> {
        self.unix_listeners.remove(service_name)
    }

    /// Wait until stunnel is ready to serve requests. Useful for testing.
    pub async fn wait_for_ready(&self) {
        self.initialized.read().await;
    }
}

impl Drop for STunnel {
    fn drop(&mut self) {
        trace!("Sending SIGKILL to stunnel");
        let _ = self.child.start_kill();

        for f in self.temp_files.drain(0..) {
            trace!("Cleaning up temporary file {}", f.display());
            drop(f);
        }
    }
}

impl<'a, 'b> std::fmt::Display for ServiceWithSocket<'a, 'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[{}]", self.service.name)?;

        write!(f, "accept = ")?;
        if let Some(host) = &self.service.accept_host {
            write!(f, "{host}:")?;
        }
        writeln!(f, "{}", self.service.accept_port)?;

        writeln!(f, "connect = {}", self.socket.display())?;
        writeln!(
            f,
            "cert = {}",
            self.service.cert.canonicalize().unwrap().display()
        )?;
        writeln!(
            f,
            "key = {}",
            self.service.key.canonicalize().unwrap().display()
        )?;

        Ok(())
    }
}

macro_rules! dynamic_event {
    ($level:expr, $($args:tt)*) => {{
        use ::tracing::Level;

        match $level {
            Level::ERROR => ::tracing::event!(Level::ERROR, $($args)*),
            Level::WARN => ::tracing::event!(Level::WARN, $($args)*),
            Level::INFO => ::tracing::event!(Level::INFO, $($args)*),
            Level::DEBUG => ::tracing::event!(Level::DEBUG, $($args)*),
            Level::TRACE => ::tracing::event!(Level::TRACE, $($args)*),
        }
    }};
}

/// Parse the stunnel logs (printed to stderr) and play them back via
/// tracing.rs. Also look for the 'Configuration successful' message
/// as a sign that it's ready to accept requests.
async fn translate_stunnel_logs(child_stderr: ChildStderr, initialized: Arc<RwLock<()>>) {
    let mut init_lock = Some(initialized.write().await);

    // stunnel formats its logs like this:
    //     stamp=str_printf("%04d.%02d.%02d %02d:%02d:%02d",
    //         timeptr->tm_year+1900, timeptr->tm_mon+1, timeptr->tm_mday,
    //         timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec);
    //     id=str_printf("LOG%d[%s]", level, tls_data->id);
    //     line=str_printf("%s %s: %s", stamp, id, text);

    // example log line:
    //   2022.06.02 09:46:19 LOG5[ui]: stunnel 5.56 on x86_64-pc-linux-gnu platform

    // - Group 1: log level
    // - Group 2: connection id, or 'ui' for application level messages
    // - Group 3: message body
    let general_msg =
        Regex::new(r"^\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2} LOG(\d)\[([\d\w]+)\]: (.*)$").unwrap();

    // Some messages have a common prefix talking about a particular service. This regex applies
    // only to the message body from the above regex.
    // - Group 1: service name
    let service_msg_body = Regex::new(r"^Service \[(.*)\] (.*)$").unwrap();

    let mut lines = BufReader::new(child_stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(general_captures) = general_msg.captures(&line) {
            // SAFETY: These unwraps are okay because we just saw the
            // regex match, so we know the capture groups will be
            // there.

            let log_level = general_captures.get(1).unwrap();
            let log_level_num: usize = log_level.as_str().parse().unwrap();
            let level = syslog_severity_to_trace_level(log_level_num);

            let connection_id = general_captures.get(2).unwrap().as_str();
            let body = general_captures.get(3).unwrap().as_str();

            if body.contains("Configuration successful") {
                if let Some(l) = init_lock.take() {
                    drop(l);
                }
            }

            if let Some(service_captures) = service_msg_body.captures(body) {
                let service = service_captures.get(1).unwrap().as_str();
                let body = service_captures.get(2).unwrap().as_str();
                dynamic_event!(level, %service, %connection_id, "{body}");
            } else {
                dynamic_event!(level, %connection_id, "{body}");
            }
        } else {
            // Can't parse the message, just pretend it's an error and spew the text
            error!("{line}");
        }
    }
}

/// stunnel uses syslog priorities. Translate them to tracing.rs levels as best we can.
fn syslog_severity_to_trace_level(n: usize) -> tracing::Level {
    match n {
        0 => tracing::Level::ERROR, // emergency
        1 => tracing::Level::ERROR, // alert
        2 => tracing::Level::ERROR, // critical
        3 => tracing::Level::ERROR, // error
        4 => tracing::Level::WARN,  // warning
        5 => tracing::Level::INFO,  // notice
        6 => tracing::Level::INFO,  // informational
        7 => tracing::Level::DEBUG, // debug
        _ => tracing::Level::ERROR, // fallback
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use tokio_stream::wrappers::UnixListenerStream;
    use warp::Filter;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn basic_server() {
        tracing_subscriber::fmt::init();

        let mut stunnel = STunnel::start(Config {
            services: vec![Service {
                name: "https".to_string(),
                accept_host: Some("localhost".to_string()),
                accept_port: 4433,
                cert: "./examples/example.cert".into(),
                key: "./examples/example.key".into(),
            }],
        })
        .await
        .unwrap();

        stunnel.wait_for_ready().await;

        let https_listener = stunnel.take_unix_listener("https").unwrap();
        let incoming = UnixListenerStream::new(https_listener);
        let routes = warp::any().map(|| "Hello, World!");
        let _server = tokio::spawn(warp::serve(routes).run_incoming(incoming));

        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let body = client
            .get("https://localhost:4433")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "Hello, World!");
    }
}
