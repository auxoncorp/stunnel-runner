use stunnel_runner::{Config, STunnel, Service};
use tokio_stream::wrappers::UnixListenerStream;
use warp::Filter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut stunnel = STunnel::start(Config {
        services: vec![Service {
            name: "https".to_string(),
            accept_host: None,
            accept_port: 4433,
            cert: "./examples/example.cert".into(),
            key: "./examples/example.key".into(),
        }],
    })
    .await
    .unwrap();

    let https_listener = stunnel.take_unix_listener("https").unwrap();
    let incoming = UnixListenerStream::new(https_listener);

    let routes = warp::any().map(|| "Hello, World!");
    tokio::spawn(warp::serve(routes).serve_incoming(incoming));

    tokio::signal::ctrl_c().await.unwrap();
}
