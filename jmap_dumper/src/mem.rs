use crate::structs::StructInfo;
use anyhow::{Context as _, Result};
use async_trait::async_trait;
use jmap::{
    EClassCastFlags, EClassFlags, ECppForm, EEnumFlags, EFunctionFlags, EObjectFlags,
    EPropertyFlags, EStructFlags,
};
use std::{
    cell::RefCell, collections::HashMap, marker::PhantomData, num::NonZero, rc::Rc, sync::Arc,
};

// --- Pod trait (merged TryFromBytes + Pod) ---

pub trait Pod: Sized {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self>;
}

macro_rules! impl_pod {
    ($($t:ty),* $(,)?) => {
        $(
            impl Pod for $t {
                fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
                    Ok(bytemuck::pod_read_unaligned(bytes))
                }
            }
        )*
    };
}

macro_rules! impl_pod_bitflags {
    ($(($t:ty, $bits_ty:ty)),* $(,)?) => {
        $(
            impl Pod for $t {
                fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
                    let bits: $bits_ty = bytemuck::pod_read_unaligned(bytes);
                    Self::from_bits(bits)
                        .ok_or_else(|| anyhow::anyhow!("Invalid {} bits: 0x{:x}", stringify!($t), bits))
                }
            }
        )*
    };
}

impl_pod!(i8, u8, i16, u16, i32, u32, i64, u64, usize, f32, f64);

impl_pod_bitflags!(
    (EObjectFlags, u32),
    (EClassCastFlags, u64),
    (EClassFlags, u32),
    (EFunctionFlags, u32),
    (EStructFlags, u32),
    (EPropertyFlags, u64),
    (EEnumFlags, u8),
);

impl Pod for ECppForm {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let discriminant: u8 = bytemuck::pod_read_unaligned(bytes);
        Self::from_repr(discriminant)
            .ok_or_else(|| anyhow::anyhow!("Invalid ECppForm discriminant: {}", discriminant))
    }
}

// --- Mem trait ---

#[async_trait(?Send)]
pub trait Mem {
    async fn read_buf(&self, address: u64, buf: &mut [u8]) -> Result<()>;
    async fn write_buf(&self, address: u64, buf: &[u8]) -> Result<()> {
        let _ = (address, buf);
        anyhow::bail!("write not supported for this memory backend")
    }
    fn clear_cache(&self) {}
}

const BLOCK_SIZE: u64 = 0x10000;

pub struct BlockCache<M> {
    inner: M,
    blocks: RefCell<HashMap<u64, Rc<BlockSlot>>>,
}

struct BlockSlot {
    /// `None` while the owning task loads it; `Some` once ready (Ok or Err).
    state: RefCell<Option<Result<Arc<[u8]>, Arc<anyhow::Error>>>>,
    ready: event_listener::Event,
}

impl<M: Mem> BlockCache<M> {
    pub fn wrap(inner: M) -> Self {
        Self {
            inner,
            blocks: RefCell::new(HashMap::new()),
        }
    }

    /// Fetch the aligned block at `base`, loading it exactly once even when several tasks race on the same miss.
    async fn block(&self, base: u64) -> Result<Arc<[u8]>> {
        // Claim or find the slot. The task that inserts it does the load; others park on the event until it's ready.
        let (slot, we_load) = {
            let mut map = self.blocks.borrow_mut();
            match map.get(&base) {
                Some(slot) => (slot.clone(), false),
                None => {
                    let slot = Rc::new(BlockSlot {
                        state: RefCell::new(None),
                        ready: event_listener::Event::new(),
                    });
                    map.insert(base, slot.clone());
                    (slot, true)
                }
            }
        };

        if we_load {
            let mut buf = vec![0u8; BLOCK_SIZE as usize];
            let result = self
                .inner
                .read_buf(base, &mut buf)
                .await
                .map(|()| Arc::from(buf))
                .map_err(Arc::new);
            *slot.state.borrow_mut() = Some(result);
            slot.ready.notify(usize::MAX);
        }

        loop {
            if let Some(result) = &*slot.state.borrow() {
                return result.clone().map_err(|e| anyhow::anyhow!("{e}"));
            }
            // Create the listener *before* re-checking so we can't miss a notify.
            let listener = slot.ready.listen();
            if slot.state.borrow().is_some() {
                continue;
            }
            listener.await;
        }
    }
}

#[async_trait(?Send)]
impl<M: Mem> Mem for BlockCache<M> {
    async fn read_buf(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let cur = address + filled as u64;
            let base = cur & !(BLOCK_SIZE - 1);
            let off = (cur - base) as usize;
            let n = (buf.len() - filled).min(BLOCK_SIZE as usize - off);
            match self.block(base).await {
                Ok(data) => buf[filled..filled + n].copy_from_slice(&data[off..off + n]),
                // Block straddles an unmapped gap: fall back to an exact,
                // uncached read of just the requested bytes (matches MinidumpMem).
                Err(_) => {
                    self.inner
                        .read_buf(cur, &mut buf[filled..filled + n])
                        .await?
                }
            }
            filled += n;
        }
        Ok(())
    }

    async fn write_buf(&self, address: u64, buf: &[u8]) -> Result<()> {
        // Invalidate any cached blocks the write overlaps, then write through.
        {
            let mut map = self.blocks.borrow_mut();
            let start = address & !(BLOCK_SIZE - 1);
            let end = (address + buf.len() as u64).saturating_sub(1) & !(BLOCK_SIZE - 1);
            let mut b = start;
            loop {
                map.remove(&b);
                if b == end {
                    break;
                }
                b += BLOCK_SIZE;
            }
        }
        self.inner.write_buf(address, buf).await
    }

    fn clear_cache(&self) {
        self.blocks.borrow_mut().clear();
    }
}

// --- ProcessHandle ---

pub struct ProcessHandle {
    pub pid: i32,
}

impl ProcessHandle {
    pub fn new(pid: i32) -> Self {
        Self { pid }
    }
}

#[cfg(target_os = "linux")]
#[async_trait(?Send)]
impl Mem for ProcessHandle {
    async fn read_buf(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        let local_iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let remote_iov = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let result = unsafe { libc::process_vm_readv(self.pid, &local_iov, 1, &remote_iov, 1, 0) };
        if result == -1 {
            anyhow::bail!(
                "process_vm_readv failed reading {} bytes at 0x{:x}: {}",
                buf.len(),
                address,
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    async fn write_buf(&self, address: u64, buf: &[u8]) -> Result<()> {
        let local_iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let remote_iov = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let result = unsafe { libc::process_vm_writev(self.pid, &local_iov, 1, &remote_iov, 1, 0) };
        if result == -1 {
            anyhow::bail!(
                "process_vm_writev failed writing {} bytes at 0x{:x}: {}",
                buf.len(),
                address,
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
#[async_trait(?Send)]
impl Mem for ProcessHandle {
    async fn read_buf(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        use read_process_memory::{CopyAddress, Pid};
        let handle: read_process_memory::ProcessHandle = (self.pid as Pid).try_into()?;
        handle
            .copy_address(address as usize, buf)
            .with_context(|| format!("reading {} bytes at 0x{:x}", buf.len(), address))
    }

    async fn write_buf(&self, address: u64, buf: &[u8]) -> Result<()> {
        use read_process_memory::Pid;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        let handle: read_process_memory::ProcessHandle = (self.pid as Pid).try_into()?;
        unsafe {
            WriteProcessMemory(
                HANDLE(*handle),
                address as *const _,
                buf.as_ptr() as *const _,
                buf.len(),
                None,
            )?;
        }
        Ok(())
    }
}

// --- Ctx ---

pub struct CtxInner {
    pub mem: Box<dyn Mem>,
    pub fnamepool: u64,
    pub structs: HashMap<String, StructInfo>,
    pub version: (u16, u16),
    pub case_preserving: bool,
    pub uobjectarray: u64,
    pub image_base_address: u64,
    pub build_change_list: Option<String>,
}

/// Shared context: single Arc clone per Ptr operation. Deref to `CtxInner` for field access.
#[derive(Clone)]
pub struct Ctx(Arc<CtxInner>);

impl Ctx {
    pub fn new(inner: CtxInner) -> Self {
        Self(Arc::new(inner))
    }

    pub async fn read_buf(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.mem.read_buf(address, buf).await
    }
    pub async fn read<T: Pod>(&self, address: u64) -> Result<T> {
        let mut buf = vec![0u8; std::mem::size_of::<T>()];
        self.mem.read_buf(address, &mut buf).await?;
        T::try_from_bytes(&buf)
    }
    pub async fn read_vec<T: Pod>(&self, address: u64, count: usize) -> Result<Vec<T>> {
        let size = std::mem::size_of::<T>();
        let mut buf = vec![0u8; count * size];
        self.mem.read_buf(address, &mut buf).await?;
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * size;
            let end = start + size;
            result.push(T::try_from_bytes(&buf[start..end])?);
        }
        Ok(result)
    }
    pub async fn write_buf(&self, address: u64, buf: &[u8]) -> Result<()> {
        self.mem.write_buf(address, buf).await
    }
    pub async fn write<T: Pod>(&self, address: u64, value: &T) -> Result<()> {
        let bytes = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.mem.write_buf(address, bytes).await
    }
    pub fn clear_cache(&self) {
        self.mem.clear_cache();
    }

    pub fn get_struct(&self, struct_name: &str) -> &StructInfo {
        let Some(s) = self.structs.get(struct_name) else {
            panic!("struct {struct_name} not found");
        };
        s
    }
    pub fn struct_member(&self, struct_name: &str, member_name: &str) -> usize {
        let Some(member) = self
            .get_struct(struct_name)
            .members
            .iter()
            .find(|m| m.name == member_name)
        else {
            panic!("struct member {struct_name}::{member_name} not found");
        };
        member.offset as usize
    }
    pub fn ue_version(&self) -> (u16, u16) {
        self.version
    }
}

impl std::ops::Deref for Ctx {
    type Target = CtxInner;
    fn deref(&self) -> &CtxInner {
        &self.0
    }
}

// --- Ptr ---

#[derive(Clone)]
pub struct Ptr<T> {
    address: NonZero<u64>,
    ctx: Ctx,
    _type: PhantomData<T>,
}
impl<T> std::fmt::Debug for Ptr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ptr(0x{:x})", self.address)
    }
}
impl<T> Ptr<T> {
    pub fn new(address: u64, ctx: Ctx) -> Result<Self> {
        Ok(Self {
            address: address.try_into().context("unexpected null ptr")?,
            ctx,
            _type: Default::default(),
        })
    }
    pub fn new_non_zero(address: NonZero<u64>, ctx: Ctx) -> Self {
        Self {
            address,
            ctx,
            _type: Default::default(),
        }
    }
    pub fn ctx(&self) -> &Ctx {
        &self.ctx
    }
    pub fn address(&self) -> u64 {
        self.address.get()
    }
    pub fn map(&self, map: impl FnOnce(u64) -> u64) -> Result<Self> {
        Self::new(map(self.address.into()), self.ctx.clone())
    }
    pub fn cast<O>(&self) -> Ptr<O> {
        Ptr::new_non_zero(self.address, self.ctx.clone())
    }
    pub fn byte_offset(&self, n: usize) -> Self {
        Self::new_non_zero(
            self.address.checked_add(n as u64).unwrap(),
            self.ctx.clone(),
        )
    }
}
// offset for Pod types (known size at compile time)
impl<T: Pod> Ptr<T> {
    pub fn offset(&self, n: usize) -> Self {
        self.byte_offset(n * std::mem::size_of::<T>())
    }
    pub async fn read(&self) -> Result<T> {
        self.ctx.read(self.address.into()).await
    }
    pub async fn read_vec(&self, count: usize) -> Result<Vec<T>> {
        self.ctx.read_vec(self.address.into(), count).await
    }
}
// offset for Ptr<Ptr<T>> (always 8 bytes)
impl<T> Ptr<Ptr<T>> {
    pub fn offset(&self, n: usize) -> Self {
        self.byte_offset(n * 8)
    }
    pub async fn read(&self) -> Result<Ptr<T>> {
        let addr = self.ctx.read::<u64>(self.address.into()).await?;
        Ok(self.map(|_| addr)?.cast())
    }
}
// offset for Ptr<Option<Ptr<T>>> (always 8 bytes)
impl<T> Ptr<Option<Ptr<T>>> {
    pub fn offset(&self, n: usize) -> Self {
        self.byte_offset(n * 8)
    }
    pub async fn read(&self) -> Result<Option<Ptr<T>>> {
        let addr = self.ctx.read::<u64>(self.address.into()).await?;
        Ok(if addr != 0 {
            Some(self.map(|_| addr)?.cast())
        } else {
            None
        })
    }
}
