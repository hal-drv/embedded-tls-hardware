use cipher::consts::{U1, U12, U16};
use cipher::{Block, BlockBackend, BlockCipher, BlockClosure, BlockEncrypt, ParBlocksSizeUser};
use cipher::{Key, KeyInit, KeySizeUser};
use digest::core_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Reset, Update};
use embedded_tls::{Aes128GcmSha256, TlsCipherSuite};
use esp_hal::aes::{AesContext, Operation, cipher_modes::Ecb};
use esp_hal::sha::Sha256Context;

#[derive(Clone)]
pub struct HwAes128([u8; 16]); // the key inside

impl KeySizeUser for HwAes128 {
    type KeySize = U16;
}

impl KeyInit for HwAes128 {
    fn new(key: &Key<Self>) -> Self {
        Self((*key).into())
    }
}

impl BlockSizeUser for HwAes128 {
    type BlockSize = U16;
}

impl BlockCipher for HwAes128 {}

impl BlockEncrypt for HwAes128 {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
        f.call(&mut self.clone());
    }
}

impl ParBlocksSizeUser for HwAes128 {
    type ParBlocksSize = U1;
}

impl BlockBackend for HwAes128 {
    fn proc_block(&mut self, mut block: cipher::inout::InOut<'_, '_, Block<Self>>) {
        let out = &mut [0; 16];
        let mut ctx = AesContext::new(Ecb, Operation::Encrypt, self.0);
        // let mut handle = ctx.process(block.get_in(), out).unwrap();
        // defmt::info!("is ready at first time: {}", handle.poll());
        // handle.wait_blocking();
        ctx.process(block.get_in(), out).unwrap().wait_blocking(); // do not be scare, mostly the data is immediately ready
        block.get_out().copy_from_slice(out);
    }
}

#[derive(Clone, Default)]
pub struct HwSha256(Sha256Context);

impl Reset for HwSha256 {
    fn reset(&mut self) {
        self.0 = Sha256Context::new();
    }
}

impl HashMarker for HwSha256 {}

impl OutputSizeUser for HwSha256 {
    type OutputSize = <Sha256Context as OutputSizeUser>::OutputSize;
}

impl BlockSizeUser for HwSha256 {
    type BlockSize = <Sha256Context as BlockSizeUser>::BlockSize;

    fn block_size() -> usize {
        Sha256Context::block_size()
    }
}

impl Update for HwSha256 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data).wait_blocking();
    }
}

impl FixedOutput for HwSha256 {
    fn finalize_into(mut self, out: &mut Output<Self>) {
        self.0.finalize(out.as_mut()).wait_blocking();
    }
}

/// Needs init hardware crypto backend before.
///
/// # Examples
///
/// ```
/// use esp_hal::aes::{AesBackend, AesWorkQueueDriver};
/// use esp_hal::sha::{ShaBackend, ShaWorkQueueDriver};
/// let aes_backend = mk_static!(AesBackend, AesBackend::new(peripherals.AES));
/// mk_static!(AesWorkQueueDriver, aes_backend.start()); // static, never drop
/// let sha_backend = mk_static!(ShaBackend, ShaBackend::new(peripherals.SHA));
/// mk_static!(ShaWorkQueueDriver, sha_backend.start()); // static, never drop
/// ```
pub struct HwAes128GcmSha256;

impl TlsCipherSuite for HwAes128GcmSha256 {
    const CODE_POINT: u16 = <Aes128GcmSha256 as TlsCipherSuite>::CODE_POINT;
    type Cipher = aes_gcm::AesGcm<HwAes128, U12, U16>; // esp-hal has no gcm so we use this
    type KeyLen = <Aes128GcmSha256 as TlsCipherSuite>::KeyLen;
    type IvLen = <Aes128GcmSha256 as TlsCipherSuite>::IvLen;
    type Hash = HwSha256;
    type LabelBufferSize = <Aes128GcmSha256 as TlsCipherSuite>::LabelBufferSize;
}
