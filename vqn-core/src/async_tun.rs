use std::assert_eq;
use std::io::{self, IoSlice, Read, Write};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::ready;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed};

pub struct Iface {
    inner: AsyncFd<Arc<tun_tap::Iface>>,
}

impl Iface {
    pub fn new(tun_name: &str) -> io::Result<Self> {
        let iface = tun_tap::Iface::without_packet_info(tun_name, tun_tap::Mode::Tun)?;

        Self::from_sync(iface)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        let inner = self.inner.get_ref();
        Ok(Self {
            inner: AsyncFd::new(Arc::clone(inner))?,
        })
    }

    pub fn into_framed(self, mtu: usize) -> Framed<Self, TunPacketCodec> {
        let codec = TunPacketCodec::new(mtu);
        Framed::new(self, codec)
    }

    fn from_sync(dev: tun_tap::Iface) -> io::Result<Self> {
        debug_assert_eq!(
            tun_tap::Mode::Tun,
            dev.mode(),
            "only Tun is supported for now"
        );
        dev.set_non_blocking()?;

        Ok(Self {
            inner: AsyncFd::new(Arc::new(dev))?,
        })
    }
}

impl std::ops::Deref for Iface {
    type Target = tun_tap::Iface;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref().deref()
    }
}

impl AsyncRead for Iface {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready_mut(cx))?;
            let rbuf = buf.initialize_unfilled();

            match guard.try_io(|inner| inner.get_ref().recv(rbuf)) {
                Ok(res) => return Poll::Ready(res.map(|n| buf.advance(n))),
                Err(_wb) => continue,
            }
        }
    }
}

impl AsyncWrite for Iface {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready_mut(cx))?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(res) => return Poll::Ready(res),
                Err(_wb) => continue,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _guard = ready!(self.inner.poll_write_ready_mut(cx))?;

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct TunPacketCodec {
    mtu: usize,
}

impl TunPacketCodec {
    pub fn new(mtu: usize) -> TunPacketCodec {
        TunPacketCodec { mtu }
    }
}

impl Decoder for TunPacketCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let pkt = buf.split_to(buf.len());

        // reserve enough space for the next packet
        buf.reserve(self.mtu);

        Ok(Some(pkt.freeze()))
    }
}

impl Encoder<Bytes> for TunPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.len());
        dst.put(item);
        Ok(())
    }
}
