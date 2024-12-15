use hex;

pub trait Sha {
    fn new() -> Self;
    fn digest(&self, input: &[u8]) -> String;
}

pub struct Sha1 {}

impl Sha1 {
    // Initial hash values
    const H: [u32; 5]= [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Round constants for SHA-1
    const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
}

impl Sha for Sha1 {
    fn new() -> Self {
        Self {}
    }
    fn digest(&self, input: &[u8]) -> String {
        let padded = pad_512(input); // Padding the input to the required block size 

        let mut h0 = Self::H[0];
        let mut h1 = Self::H[1];
        let mut h2 = Self::H[2];
        let mut h3 = Self::H[3];
        let mut h4 = Self::H[4];

        for chunk in padded.chunks(64) {
            let mut w = [0u32; 80];

            // Prepare message schedule
            for i in 0..16 {
                w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
            }

            // Extend the message schedule
            for i in 16..80 {
                w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
                w[i] = rotl_32(w[i], 1);
            }

            let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

            for i in 0..80 {
                let (f, k) = if i < 20 {
                    (ch_32(b, c, d), Self::K[0])
                } else if i < 40 {
                    (parity_32(b, c, d), Self::K[1])
                } else if i < 60 {
                    (maj_32(b, c, d), Self::K[2])
                } else {
                    (parity_32(b, c, d), Self::K[3])
                };

                let temp = rotl_32(a, 5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = rotl_32(b, 30);
                b = a;
                a = temp;
            }

            // Update the hash values
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }

        // Convert final hash values to bytes
        let mut hash = [0u8; 20];
        hash[..4].copy_from_slice(&h0.to_be_bytes());
        hash[4..8].copy_from_slice(&h1.to_be_bytes());
        hash[8..12].copy_from_slice(&h2.to_be_bytes());
        hash[12..16].copy_from_slice(&h3.to_be_bytes());
        hash[16..20].copy_from_slice(&h4.to_be_bytes());

        hex::encode(hash) // Convert the bytes to a hex string
    }
}

pub struct Sha256 {}

impl Sha256 {
    // Initial hash values
    const H: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Round constants for SHA-256
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
}

impl Sha for Sha256 {
    fn new() -> Self {
        Self {}
    }
    fn digest(&self, input: &[u8]) -> String {
        let padded = pad_512(input); // Padding the input to the required block size

        let mut h0 = Self::H[0];
        let mut h1 = Self::H[1];
        let mut h2 = Self::H[2];
        let mut h3 = Self::H[3];
        let mut h4 = Self::H[4];
        let mut h5 = Self::H[5];
        let mut h6 = Self::H[6];
        let mut h7 = Self::H[7];

        for chunk in padded.chunks(64) {
            let mut w = [0u32; 64];

            // Prepare message schedule
            for i in 0..16 {
                w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
            }

            // Extend the message schedule
            for i in 16..64 {
                w[i] = delta1_32(w[i - 2])
                    .wrapping_add(w[i - 7])
                    .wrapping_add(delta0_32(w[i - 15]))
                    .wrapping_add(w[i - 16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
                (h0, h1, h2, h3, h4, h5, h6, h7);

            for i in 0..64 {
                let t1 = h
                    .wrapping_add(sigma1_32(e))
                    .wrapping_add(ch_32(e, f, g))
                    .wrapping_add(Self::K[i])
                    .wrapping_add(w[i]);
                let t2 = sigma0_32(a).wrapping_add(maj_32(a, b, c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            // Update the hash values
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
            h5 = h5.wrapping_add(f);
            h6 = h6.wrapping_add(g);
            h7 = h7.wrapping_add(h);
        }
        
        // Convert final hash values to bytes
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&h0.to_be_bytes());
        hash[4..8].copy_from_slice(&h1.to_be_bytes());
        hash[8..12].copy_from_slice(&h2.to_be_bytes());
        hash[12..16].copy_from_slice(&h3.to_be_bytes());
        hash[16..20].copy_from_slice(&h4.to_be_bytes());
        hash[20..24].copy_from_slice(&h5.to_be_bytes());
        hash[24..28].copy_from_slice(&h6.to_be_bytes());
        hash[28..32].copy_from_slice(&h7.to_be_bytes());

        hex::encode(hash) // Convert the bytes to a hex string
    }
}

pub struct Sha512 {}

impl Sha512 {
    // Initial hash values
    const H: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    // Round constants for SHA-512
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];
}

impl Sha for Sha512 {
    fn new() -> Self {
        Self {}
    }
    fn digest(&self, input: &[u8]) -> String {
        let padded = pad_1024(input);

        let mut h0 = Self::H[0];
        let mut h1 = Self::H[1];
        let mut h2 = Self::H[2];
        let mut h3 = Self::H[3];
        let mut h4 = Self::H[4];
        let mut h5 = Self::H[5];
        let mut h6 = Self::H[6];
        let mut h7 = Self::H[7];

        for chunk in padded.chunks(128) {
            let mut w = [0u64; 80];

            // Prepare message schedule
            for i in 0..16 {
                w[i] = u64::from_be_bytes(chunk[i * 8..(i + 1) * 8].try_into().unwrap());
            }

            // Extend the message schedule
            for i in 16..80 {
                w[i] = delta1_64(w[i - 2])
                    .wrapping_add(w[i - 7])
                    .wrapping_add(delta0_64(w[i - 15]))
                    .wrapping_add(w[i - 16]);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
                (h0, h1, h2, h3, h4, h5, h6, h7);

            for i in 0..80 {
                let t1 = h
                    .wrapping_add(sigma1_64(e))
                    .wrapping_add(ch_64(e, f, g))
                    .wrapping_add(Self::K[i])
                    .wrapping_add(w[i]);
                let t2 = sigma0_64(a).wrapping_add(maj_64(a, b, c));

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            // Update the hash values
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
            h5 = h5.wrapping_add(f);
            h6 = h6.wrapping_add(g);
            h7 = h7.wrapping_add(h);
        }

        // Convert final hash values to bytes
        let mut hash = [0u8; 64];
        hash[..8].copy_from_slice(&h0.to_be_bytes());
        hash[8..16].copy_from_slice(&h1.to_be_bytes());
        hash[16..24].copy_from_slice(&h2.to_be_bytes());
        hash[24..32].copy_from_slice(&h3.to_be_bytes());
        hash[32..40].copy_from_slice(&h4.to_be_bytes());
        hash[40..48].copy_from_slice(&h5.to_be_bytes());
        hash[48..56].copy_from_slice(&h6.to_be_bytes());
        hash[56..64].copy_from_slice(&h7.to_be_bytes());

        hex::encode(hash) // Convert the bytes to a hex string
    }
}

// UTILITY FUNCTIONS

fn ch_32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj_32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn parity_32(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn rotr_32(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn rotl_32(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn sigma0_32(x: u32) -> u32 {
    rotr_32(x, 2) ^ rotr_32(x, 13) ^ rotr_32(x, 22)
}

fn sigma1_32(x: u32) -> u32 {
    rotr_32(x, 6) ^ rotr_32(x, 11) ^ rotr_32(x, 25)
}

fn delta0_32(x: u32) -> u32 {
    rotr_32(x, 7) ^ rotr_32(x, 18) ^ shr_32(x, 3)
}

fn delta1_32(x: u32) -> u32 {
    rotr_32(x, 17) ^ rotr_32(x, 19) ^ shr_32(x, 10)
}

fn shr_32(x: u32, n: u32) -> u32 {
    x >> n
}

fn ch_64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

fn maj_64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn rotr_64(x: u64, n: u64) -> u64 {
    (x >> n) | (x << (64 - n))
}

fn sigma0_64(x: u64) -> u64 {
    rotr_64(x, 28) ^ rotr_64(x, 34) ^ rotr_64(x, 39)
}

fn sigma1_64(x: u64) -> u64 {
    rotr_64(x, 14) ^ rotr_64(x, 18) ^ rotr_64(x, 41)
}

fn delta0_64(x: u64) -> u64 {
    rotr_64(x, 1) ^ rotr_64(x, 8) ^ shr_64(x, 7)
}

fn delta1_64(x: u64) -> u64 {
    rotr_64(x, 19) ^ rotr_64(x, 61) ^ shr_64(x, 6)
}

fn shr_64(x: u64, n: u64) -> u64 {
    x >> n
}

fn pad_512(input: &[u8]) -> Vec<u8> {
    let mut padded = input.to_vec();
    padded.push(0x80);

    while (padded.len() * 8) % 512 != 448 {
        padded.push(0);
    }

    let bit_len = (input.len() as u64) * 8;
    padded.extend_from_slice(&bit_len.to_be_bytes());

    padded
}

fn pad_1024(input: &[u8]) -> Vec<u8> {
    let mut padded = input.to_vec();
    padded.push(0x80);

    while (padded.len() * 8) % 1024 != 896 {
        padded.push(0);
    }

    let bit_len = (input.len() as u128) * 8;
    padded.extend_from_slice(&bit_len.to_be_bytes());

    padded
}

// TESTS are from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA_All.pdf

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        let sha1 = Sha1::new();
        let input1 = b"abc";
        let input2 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected_hash1 = "a9993e364706816aba3e25717850c26c9cd0d89d";
        let expected_hash2 = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
        let hash1 = sha1.digest(input1);
        let hash2 = sha1.digest(input2);

        assert_eq!(expected_hash1, hash1);
        assert_eq!(expected_hash2, hash2);
    }

    #[test]
    fn test_sha256() {
        let sha256 = Sha256::new();
        let input1 = b"abc";
        let input2 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected_hash1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let expected_hash2 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        let hash1 = sha256.digest(input1);
        let hash2 = sha256.digest(input2);

        assert_eq!(expected_hash1, hash1);
        assert_eq!(expected_hash2, hash2);
    }

    #[test]
    fn test_sha512() {
        let sha512 = Sha512::new();
        let input1 = b"abc";
        let input2 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected_hash1 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let expected_hash2 = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
        let hash1 = sha512.digest(input1);
        let hash2 = sha512.digest(input2);

        assert_eq!(expected_hash1, hash1);
        assert_eq!(expected_hash2, hash2);
    }
}
