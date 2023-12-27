use std::io::{self, IoSlice, Read, Write};

use bytes::{BufMut, Bytes, BytesMut};
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::ready;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tun::platform::Device;

pub struct Iface {
    inner: AsyncFd<Device>,
}

impl Iface {
    pub fn new(mut config: tun::Configuration) -> tun::Result<Self> {
        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        let dev = tun::create(&config)?;
        // NOTE: easy to forget and leads to unpredictable meltdowns of async runtime
        dev.set_nonblock()?;

        Ok(Self {
            inner: AsyncFd::new(dev)?,
        })
    }

    pub fn into_framed(self, mtu: usize) -> Framed<Self, TunPacketCodec> {
        let codec = TunPacketCodec::new(mtu);
        Framed::new(self, codec)
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

            match guard.try_io(|inner| inner.get_mut().read(rbuf)) {
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
            match guard.try_io(|inner| inner.get_mut().write(buf)) {
                Ok(res) => return Poll::Ready(res),
                Err(_wb) => continue,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready_mut(cx))?;
            match guard.try_io(|inner| inner.get_mut().flush()) {
                Ok(res) => return Poll::Ready(res),
                Err(_wb) => continue,
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready_mut(cx))?;
            match guard.try_io(|inner| inner.get_mut().write_vectored(bufs)) {
                Ok(res) => return Poll::Ready(res),
                Err(_wb) => continue,
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
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
