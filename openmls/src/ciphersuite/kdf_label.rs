use std::io::Write;

use tls_codec::{Serialize, Size, TlsVarInt, VLByteSlice};

use super::*;

/// `KdfLabel` is later serialized and used in the `label` field of
/// `kdf_expand_label`.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     uint16 length = Length;
///     opaque label<V> = "MLS 1.0 " + Label;
///     opaque context<V> = Context;
/// } KDFLabel;
/// ```
#[derive(Debug, TlsSerialize, TlsSize)]
pub(in crate::ciphersuite) struct KdfLabel<'a> {
    length: u16,
    label: PrefixedLabel<'a>,
    context: VLByteSlice<'a>,
}

impl KdfLabel<'_> {
    /// Serialize this label.
    /// Returns the serialized label as byte vector or returns a [`CryptoError`]
    /// if the parameters are invalid.
    pub(in crate::ciphersuite) fn serialized_label(
        context: &[u8],
        label: &str,
        length: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        if length > u16::MAX as usize {
            debug_assert!(
                false,
                "Library error: Trying to derive a key with a too large length field!"
            );
            return Err(CryptoError::KdfLabelTooLarge);
        }
        let kdf_label = KdfLabel {
            length: length as u16,
            label: PrefixedLabel(label),
            context: VLByteSlice(context),
        };
        log::trace!("{kdf_label:?}");
        kdf_label
            .tls_serialize_detached()
            .map_err(|_| CryptoError::KdfSerializationError)
    }
}

/// Serializes as the VL vector `"MLS 1.0 " || label`.
#[derive(Debug)]
struct PrefixedLabel<'a>(&'a str);

impl PrefixedLabel<'_> {
    fn content_len(&self) -> usize {
        LABEL_PREFIX.len() + self.0.len()
    }

    fn header(&self) -> Result<TlsVarInt, tls_codec::Error> {
        TlsVarInt::try_from(self.content_len() as u64)
    }
}

impl Size for PrefixedLabel<'_> {
    fn tls_serialized_len(&self) -> usize {
        let header = self.header().map(|h| h.tls_serialized_len()).unwrap_or(0);
        header + self.content_len()
    }
}

impl Serialize for PrefixedLabel<'_> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let header = self.header()?.tls_serialize(writer)?;
        writer.write_all(LABEL_PREFIX.as_bytes())?;
        writer.write_all(self.0.as_bytes())?;
        Ok(header + self.content_len())
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::VLBytes;

    use super::*;

    /// Reference encoding built the straightforward but naive way
    #[derive(TlsSerialize, TlsSize)]
    struct ReferenceKdfLabel {
        length: u16,
        label: VLBytes,
        context: VLBytes,
    }

    fn reference(context: &[u8], label: &str, length: usize) -> Vec<u8> {
        ReferenceKdfLabel {
            length: length as u16,
            label: format!("{LABEL_PREFIX}{label}").into_bytes().into(),
            context: context.to_vec().into(),
        }
        .tls_serialize_detached()
        .unwrap()
    }

    #[test]
    fn serialized_label_matches_hand_computed_bytes() {
        let serialized = KdfLabel::serialized_label(&[1, 2, 3], "secret", 32).unwrap();

        let mut expected = vec![0x00, 0x20]; // length = 32, u16 big endian
        expected.push(14); // VL header: len("MLS 1.0 secret")
        expected.extend_from_slice(b"MLS 1.0 secret");
        expected.push(3); // VL header: len(context)
        expected.extend_from_slice(&[1, 2, 3]);

        assert_eq!(serialized, expected);
    }

    #[test]
    fn serialized_label_matches_reference_encoding() {
        // Labels and contexts long enough to need a 2-byte VL header (> 63
        // bytes) and a context that needs a 3-byte header (> 16383 bytes).
        let long_label = "x".repeat(100);
        let long_context = vec![0xab; 200];
        let huge_context = vec![0xcd; 20_000];

        let cases: &[(&[u8], &str, usize)] = &[
            (&[], "", 0),
            (&[], "secret", 32),
            (&[1, 2, 3], "secret", 32),
            (&long_context, "nonce", 12),
            (&[7; 32], &long_label, 64),
            (&huge_context, &long_label, u16::MAX as usize),
        ];

        for &(context, label, length) in cases {
            let serialized = KdfLabel::serialized_label(context, label, length).unwrap();
            assert_eq!(
                serialized,
                reference(context, label, length),
                "mismatch for label {label:?}, context len {}, length {length}",
                context.len()
            );
        }
    }

    #[test]
    fn tls_serialized_len_matches_output() {
        let long_label = "y".repeat(70);
        let cases: &[(&[u8], &str)] = &[(&[], ""), (&[1, 2, 3], "secret"), (&[0; 64], &long_label)];

        for &(context, label) in cases {
            let kdf_label = KdfLabel {
                length: 16,
                label: PrefixedLabel(label),
                context: VLByteSlice(context),
            };
            let serialized = kdf_label.tls_serialize_detached().unwrap();
            assert_eq!(kdf_label.tls_serialized_len(), serialized.len());
            assert_eq!(
                kdf_label.label.tls_serialized_len(),
                1 + LABEL_PREFIX.len()
                    + label.len()
                    + usize::from(label.len() + LABEL_PREFIX.len() > 63)
            );
        }
    }
}
