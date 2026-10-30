// The key that signs pano releases (Ed25519, over SHA256SUMS). The private half
// lives only in the repository's PANO_RELEASE_KEY secret; a fork that publishes
// its own releases sets PANO_RELEASE_PUBKEY to its own public key.
export const RELEASE_PUBKEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9lt4OZWuOwWbBaaBlgtzcuzVwi3T/LZDJTpM0Q3wa8Y=
-----END PUBLIC KEY-----
`;
