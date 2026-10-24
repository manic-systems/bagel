use std::{
   error::Error as StdError,
   future::Future,
   io,
   net::SocketAddr,
   path::Path,
   pin::Pin,
   task::{
      Context,
      Poll,
   },
   time::Duration,
};

use http::Uri;
use hyper_util::{
   client::legacy::{
      Client,
      connect::{
         Connected,
         Connection,
         HttpConnector,
      },
   },
   rt::{
      TokioExecutor,
      TokioIo,
   },
};
use tokio::{
   io::{
      AsyncRead,
      AsyncWrite,
      ReadBuf,
   },
   net::{
      TcpStream,
      UnixStream,
   },
};
use tower_service::Service;

use crate::{
   body::Body,
   proxy::backend::{
      Upstream,
      unix_socket_path,
   },
};

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub type UpstreamClient = Client<UpstreamConnector, Body>;

#[must_use]
pub fn build_http_client() -> UpstreamClient {
   let mut http = HttpConnector::new();
   http.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));
   Client::builder(TokioExecutor::new()).build(UpstreamConnector { http })
}

/// Open a connection that bypasses the pooled client.
pub async fn connect(upstream: &Upstream) -> io::Result<UpstreamStream> {
   match upstream {
      Upstream::Tcp(authority) => {
         let address = format!(
            "{}:{}",
            authority.host(),
            authority.port_u16().unwrap_or(80)
         );
         tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map(UpstreamStream::Tcp)
      },
      Upstream::Unix(path) => connect_unix(path).await,
   }
}

async fn connect_unix(path: &Path) -> io::Result<UpstreamStream> {
   tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, UnixStream::connect(path))
      .await
      .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
      .map(UpstreamStream::Unix)
}

pub enum UpstreamStream {
   Tcp(TcpStream),
   Unix(UnixStream),
}

impl UpstreamStream {
   pub fn addresses(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
      match self {
         Self::Tcp(stream) => (stream.local_addr().ok(), stream.peer_addr().ok()),
         Self::Unix(_) => (None, None),
      }
   }
}

impl AsyncRead for UpstreamStream {
   fn poll_read(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      buf: &mut ReadBuf<'_>,
   ) -> Poll<io::Result<()>> {
      match self.get_mut() {
         Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
         Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
      }
   }
}

impl AsyncWrite for UpstreamStream {
   fn poll_write(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      buf: &[u8],
   ) -> Poll<io::Result<usize>> {
      match self.get_mut() {
         Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
         Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
      }
   }

   fn poll_write_vectored(
      self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      bufs: &[io::IoSlice<'_>],
   ) -> Poll<io::Result<usize>> {
      match self.get_mut() {
         Self::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
         Self::Unix(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
      }
   }

   fn is_write_vectored(&self) -> bool {
      match self {
         Self::Tcp(stream) => stream.is_write_vectored(),
         Self::Unix(stream) => stream.is_write_vectored(),
      }
   }

   fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      match self.get_mut() {
         Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
         Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
      }
   }

   fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      match self.get_mut() {
         Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
         Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
      }
   }
}

impl Connection for UpstreamStream {
   fn connected(&self) -> Connected {
      match self {
         Self::Tcp(stream) => stream.connected(),
         Self::Unix(stream) => stream.connected(),
      }
   }
}

#[derive(Clone)]
pub struct UpstreamConnector {
   http: HttpConnector,
}

type BoxError = Box<dyn StdError + Send + Sync>;

impl Service<Uri> for UpstreamConnector {
   type Error = BoxError;
   type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
   type Response = TokioIo<UpstreamStream>;

   fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
      self.http.poll_ready(cx).map_err(Into::into)
   }

   fn call(&mut self, req: Uri) -> Self::Future {
      if let Some(path) = unix_socket_path(&req) {
         return Box::pin(async move { Ok(TokioIo::new(connect_unix(&path).await?)) });
      }

      let connecting = self.http.call(req);
      Box::pin(async move {
         let io = connecting.await?;
         Ok(TokioIo::new(UpstreamStream::Tcp(io.into_inner())))
      })
   }
}
