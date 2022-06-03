# stunnel-runner

This is a library which makes it easy to run stunnel as a child process in your Rust application. 

## The situation

Rust has two commonly used SSL libraries: Rustls and native-tls. Rustls is a rust-based implementation of TLS. It integrates well with many rust libraries, but there are two important reasons NOT to use it:
- If you're shipping on-prem software, some customers won't accept it. 
- If there's a CVE that impacts Rustls, you have to rebuild and re-ship your software. 

What of native-tls? It evidently doesn't work well with async rust libraries, leading to data corruption: https://github.com/tokio-rs/tls/issues/41 . The warp web server library in particular doesn't support it, probably for this reason.

## The solution

So instead, we can use stunnel. It's commonly available on any Linux system, and it uses OpenSSL.  Warp can run on a unix domain socket, and stunnel can proxy TLS to that. This crate makes it really easy to do that. 

See the [example](./examples/warp_server.rs) for how to do it. 

Features:

* The library will set up the domain sockets for you, managed as temp files.

* You can run multiple proxies at once, using a single stunnel instance. These 'services' in stunnel parlence. 

* stunnel logs are parsed and emitted using `tracing.rs`. 

## Limitations

* You have to make sure stunnel is installed. 

* This only works on unix, and is only tested on Linux. It's probably possible to do this on Windows, but I haven't thought about it.

