//! TLS 1.3 with X25519MLKEM768 as the ONLY key-exchange group: a server that does not offer it is refused
//! (no classical fallback), exactly like the oneqrelay side.
use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::{ClientConfig, RootCertStore};

/// `ca_pem`: extra trusted certificate(s) (a private CA or a self-signed relay certificate). When given, ONLY these
/// are trusted; otherwise the Mozilla root set is used (works for Let's Encrypt certificates).
pub fn client_config(ca_pem: Option<&[u8]>) -> Result<Arc<ClientConfig>> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![kx_group::X25519MLKEM768];
    let mut roots = RootCertStore::empty();
    match ca_pem {
        Some(pem) => {
            let mut n = 0;
            for cert in rustls_pemfile::certs(&mut &pem[..]) {
                roots.add(cert.map_err(|e| anyhow!("bad CA certificate: {e}"))?)?;
                n += 1;
            }
            if n == 0 {
                return Err(anyhow!("no certificate found in the CA file"));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn only_the_hybrid_group_is_offered() {
        let cfg = client_config(None).unwrap();
        let groups: Vec<_> = cfg.crypto_provider().kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();
        assert_eq!(groups, vec!["X25519MLKEM768"]);
        assert!(client_config(Some(b"not a certificate")).is_err());
    }

    /// A real TLS 1.3 handshake against a server that supports only the hybrid group works, and one that supports
    /// only classical groups is refused.
    #[tokio::test]
    async fn handshake_with_pq_server_ok_classical_server_refused() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // a throw-away self-signed certificate
        let (cert_pem, key_der) = self_signed();
        let cert_der = CertificateDer::from(rustls_pemfile::certs(&mut &cert_pem[..]).next().unwrap().unwrap());

        async fn serve(groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>, cert: CertificateDer<'static>, key: Vec<u8>) -> u16 {
            let mut p = aws_lc_rs::default_provider();
            p.kx_groups = groups;
            let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(p))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], PrivateKeyDer::try_from(key).unwrap())
                .unwrap();
            let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = l.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let (s, _) = l.accept().await.unwrap();
                    let acc = acc.clone();
                    tokio::spawn(async move {
                        if let Ok(mut t) = acc.accept(s).await {
                            let _ = t.write_all(b"hi").await;
                            let _ = t.shutdown().await;
                        }
                    });
                }
            });
            port
        }

        let pq = serve(vec![kx_group::X25519MLKEM768], cert_der.clone(), key_der.clone()).await;
        let classical = serve(vec![kx_group::X25519], cert_der.clone(), key_der.clone()).await;
        let conn = tokio_rustls::TlsConnector::from(client_config(Some(&cert_pem)).unwrap());
        let name = ServerName::try_from("localhost").unwrap();

        let tcp = TcpStream::connect(("127.0.0.1", pq)).await.unwrap();
        let mut tls = conn.connect(name.clone(), tcp).await.expect("PQ server must work");
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.ok();
        assert_eq!(buf, b"hi");

        let tcp = TcpStream::connect(("127.0.0.1", classical)).await.unwrap();
        assert!(conn.connect(name, tcp).await.is_err(), "a server without X25519MLKEM768 must be refused");
    }

    fn self_signed() -> (Vec<u8>, Vec<u8>) {
        // generated once with: openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=localhost
        //   -addext subjectAltName=DNS:localhost -days 36500
        const CERT: &str = include_str!("../testdata/localhost.crt");
        const KEY: &str = include_str!("../testdata/localhost.key");
        let key = rustls_pemfile::private_key(&mut KEY.as_bytes()).unwrap().unwrap();
        (CERT.as_bytes().to_vec(), key.secret_der().to_vec())
    }
}
