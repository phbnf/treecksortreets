/**
 * Merkle Tree library for Web Visualization.
 * Implements RFC 6962 / Certificate Transparency style Merkle Trees.
 */

// --- Pure JavaScript SHA-256 implementation ---
function rightRotate(v, n) {
  return ((v >>> n) | (v << (32 - n))) >>> 0;
}

function sha256(bytes) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  const len = bytes.length;
  const bitLen = len * 8;
  const padLen = (bitLen % 512 < 448) ? (448 - bitLen % 512) : (960 - bitLen % 512);
  const totalLen = len + (padLen / 8) + 8;
  const buffer = new Uint8Array(totalLen);
  buffer.set(bytes);
  buffer[len] = 0x80;
  
  const view = new DataView(buffer.buffer);
  view.setBigUint64(totalLen - 8, BigInt(bitLen), false);

  let H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a,
      H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

  const W = new Uint32Array(64);
  for (let i = 0; i < totalLen; i += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3)) >>> 0;
      const s1 = (rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10)) >>> 0;
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }

    let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;

    for (let t = 0; t < 64; t++) {
      const S1 = (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H0 = (H0 + a) >>> 0;
    H1 = (H1 + b) >>> 0;
    H2 = (H2 + c) >>> 0;
    H3 = (H3 + d) >>> 0;
    H4 = (H4 + e) >>> 0;
    H5 = (H5 + f) >>> 0;
    H6 = (H6 + g) >>> 0;
    H7 = (H7 + h) >>> 0;
  }

  const result = new Uint8Array(32);
  const resView = new DataView(result.buffer);
  resView.setUint32(0, H0, false);
  resView.setUint32(4, H1, false);
  resView.setUint32(8, H2, false);
  resView.setUint32(12, H3, false);
  resView.setUint32(16, H4, false);
  resView.setUint32(20, H5, false);
  resView.setUint32(24, H6, false);
  resView.setUint32(28, H7, false);
  return result;
}

// --- Encoding helpers ---
export function bytesToHex(bytes) {
  if (!bytes) return '';
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  if (!hex) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function stringToBytes(str) {
  return new TextEncoder().encode(str);
}

// --- Hash utility for RFC 6962 ---
export const Hasher = {
  hashLeaf(leafBytes) {
    const buf = new Uint8Array(1 + leafBytes.length);
    buf[0] = 0x00; // Leaf prefix
    buf.set(leafBytes, 1);
    return sha256(buf);
  },

  hashChildren(leftBytes, rightBytes) {
    const buf = new Uint8Array(1 + leftBytes.length + rightBytes.length);
    buf[0] = 0x01; // Internal node prefix
    buf.set(leftBytes, 1);
    buf.set(rightBytes, 1 + leftBytes.length);
    return sha256(buf);
  },

  emptyRoot() {
    return sha256(new Uint8Array(0));
  }
};

// --- Compact Merkle Tree Math Helper ---
function decompose(begin, end) {
  if (begin === 0) {
    return [0, end];
  }
  const xbegin = begin - 1;
  const xor = xbegin ^ end;
  const d = xor === 0 ? 0 : xor.toString(2).length - 1;
  const mask = (1 << d) - 1;
  return [(~xbegin) & mask, end & mask];
}

function getTrailingZeros(n) {
  if (n === 0) return 32;
  return n.toString(2).split('').reverse().indexOf('1');
}

function getRangeNodes(begin, end) {
  const [left, right] = decompose(begin, end);
  const ids = [];
  let pos = begin;

  // Left part: LSB to MSB
  let tempLeft = left;
  while (tempLeft !== 0) {
    const level = getTrailingZeros(tempLeft);
    const bit = 1 << level;
    ids.push({ level, index: pos >> level });
    pos += bit;
    tempLeft ^= bit;
  }

  // Right part: MSB to LSB
  let tempRight = right;
  const rightIds = [];
  while (tempRight !== 0) {
    const level = tempRight.toString(2).length - 1;
    const bit = 1 << level;
    rightIds.push({ level, index: pos >> level });
    pos += bit;
    tempRight ^= bit;
  }
  ids.push(...rightIds);
  return ids;
}

function getRangeSize(begin, end) {
  const [left, right] = decompose(begin, end);
  return countOnes(left) + countOnes(right);
}

function countOnes(n) {
  if (n === 0) return 0;
  return n.toString(2).split('1').length - 1;
}

function getProofNodes(index, level, size) {
  const xor = index ^ (size >> level);
  const inner = xor === 0 ? 0 : xor.toString(2).length - 1;
  const forkLevel = level + inner;
  const forkIndex = index >> inner;

  const fork = { level: forkLevel, index: forkIndex };
  const begin = forkIndex << forkLevel;
  const end = (forkIndex + 1) << forkLevel;

  const leftSize = getRangeSize(0, begin);
  const rightSize = getRangeSize(end, size);

  const node = { level, index };
  const proof = [node];

  let curr = { ...node };
  while (curr.level < fork.level) {
    const sibling = { level: curr.level, index: curr.index ^ 1 };
    proof.push(sibling);
    curr = { level: curr.level + 1, index: Math.floor(curr.index / 2) };
  }

  const len1 = proof.length;

  const rightNodes = getRangeNodes(end, size);
  rightNodes.reverse();
  proof.push(...rightNodes);
  const len2 = proof.length;

  const leftNodes = getRangeNodes(0, begin);
  leftNodes.reverse();
  proof.push(...leftNodes);

  let beginIdx = len1;
  let endIdx = len2;
  if (len1 >= len2) {
    beginIdx = 0;
    endIdx = 0;
  }

  const ephem = { level: fork.level, index: fork.index ^ 1 };

  return {
    IDs: proof,
    begin: beginIdx,
    end: endIdx,
    ephem: ephem
  };
}

// --- Merkle Tree Class ---
export class MerkleTree {
  /**
   * @param {Array<string|Uint8Array>} leaves Initial leaves
   */
  constructor(leaves = []) {
    this.leaves = [];
    this.levels = [];
    this.setLeaves(leaves);
  }

  /**
   * Set or reset the leaves of the tree and compute hashes.
   * @param {Array<string|Uint8Array>} leaves
   */
  setLeaves(leaves) {
    this.leaves = leaves.map(l => typeof l === 'string' ? stringToBytes(l) : l);
    this.rebuild();
  }

  /**
   * Add a single leaf to the tree.
   * @param {string|Uint8Array} leaf
   */
  addLeaf(leaf) {
    const leafBytes = typeof leaf === 'string' ? stringToBytes(leaf) : leaf;
    this.leaves.push(leafBytes);
    this.rebuild();
  }

  /**
   * Rebuild the entire tree level hashes.
   */
  rebuild() {
    this.levels = [];
    const n = this.leaves.length;
    if (n === 0) {
      this.levels.push([Hasher.emptyRoot()]);
      return;
    }

    // Compute leaf hashes
    const leafHashes = this.leaves.map(l => Hasher.hashLeaf(l));
    this.levels.push(leafHashes);

    // Compute parent levels
    let currentLevel = leafHashes;
    while (currentLevel.length > 1) {
      const nextLevel = [];
      const m = currentLevel.length;
      const nextLevelSize = Math.ceil(m / 2);
      for (let i = 0; i < nextLevelSize; i++) {
        if (2 * i + 1 < m) {
          nextLevel.push(Hasher.hashChildren(currentLevel[2 * i], currentLevel[2 * i + 1]));
        } else {
          // Ephemeral node (carries over left child's hash)
          nextLevel.push(currentLevel[2 * i]);
        }
      }
      this.levels.push(nextLevel);
      currentLevel = nextLevel;
    }
  }

  /**
   * Get the root hash of the tree.
   * @returns {Uint8Array}
   */
  getRootHash() {
    if (this.levels.length === 0) return Hasher.emptyRoot();
    return this.levels[this.levels.length - 1][0];
  }

  /**
   * Get root hash as a hex string.
   * @returns {string}
   */
  getRootHashHex() {
    return bytesToHex(this.getRootHash());
  }

  /**
   * Get the hash at a specific coordinate.
   * @param {number} level
   * @param {number} index
   * @returns {Uint8Array|null}
   */
  getHash(level, index) {
    if (level < 0 || level >= this.levels.length) return null;
    if (index < 0 || index >= this.levels[level].length) return null;
    return this.levels[level][index];
  }

  /**
   * Generate an inclusion proof for a leaf index.
   * @param {number} index Leaf index
   * @returns {Array<Uint8Array>} List of sibling hashes in the proof
   */
  getInclusionProof(index) {
    const size = this.leaves.length;
    if (index < 0 || index >= size) {
      throw new Error(`Leaf index ${index} out of bounds for size ${size}`);
    }

    let idx = index;
    const proof = [];
    for (let L = 0; L < this.levels.length - 1; L++) {
      const siblingIdx = idx ^ 1;
      if (siblingIdx < this.levels[L].length) {
        proof.push(this.levels[L][siblingIdx]);
      }
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  /**
   * Generate a consistency proof between size1 and size2.
   * @param {number} size1 Old tree size
   * @param {number} size2 New tree size
   * @returns {Array<Uint8Array>} List of hashes for the consistency proof
   */
  getConsistencyProof(size1, size2) {
    if (size1 < 0 || size2 < 0 || size1 > size2) {
      throw new Error(`Invalid sizes: size1=${size1}, size2=${size2}`);
    }
    if (size1 === size2 || size1 === 0) {
      return [];
    }

    // Find root of biggest perfect subtree ending at size1
    // Trailing zeros of size1
    const trailingZeros = getTrailingZeros(size1);
    const level = trailingZeros;
    const index = (size1 - 1) >> level;

    // Get nodes of inclusion proof into this node in size2
    const p = getProofNodes(index, level, size2);

    const ids = p.IDs;
    // If size1 is a power of 2, skip the first ID
    const startIdx = (index === 0) ? 1 : 0;
    
    const proofHashes = [];
    for (let i = startIdx; i < ids.length; i++) {
      const id = ids[i];
      const h = this.getHash(id.level, id.index);
      if (h) {
        proofHashes.push(h);
      }
    }
    return proofHashes;
  }

  /**
   * Export all tree nodes and connections for visualization.
   * @returns {Object} { nodes: Array, links: Array }
   */
  getVisualizationData() {
    const nodes = [];
    const links = [];
    const n = this.leaves.length;
    if (n === 0) {
      const emptyHash = bytesToHex(Hasher.emptyRoot());
      nodes.push({
        id: "L0_I0",
        level: 0,
        index: 0,
        hash: emptyHash,
        shortHash: emptyHash.substring(0, 6) + "...",
        isLeaf: true,
        value: "Empty Tree",
        isEphemeral: false
      });
      return { nodes, links };
    }

    // Generate nodes
    for (let L = 0; L < this.levels.length; L++) {
      const levelHashes = this.levels[L];
      for (let I = 0; I < levelHashes.length; I++) {
        const hexHash = bytesToHex(levelHashes[I]);
        const isLeaf = L === 0;
        const isEphemeral = L > 0 && (2 * I + 1 >= this.levels[L - 1].length);
        
        nodes.push({
          id: `L${L}_I${I}`,
          level: L,
          index: I,
          hash: hexHash,
          shortHash: hexHash.substring(0, 6) + "...",
          isLeaf,
          value: isLeaf ? new TextDecoder().decode(this.leaves[I]) : null,
          isEphemeral
        });

        // Add links to children
        if (L > 0) {
          const leftChildId = `L${L - 1}_I${2 * I}`;
          links.push({
            id: `edge_L${L}_I${I}_to_${leftChildId}`,
            source: `L${L}_I${I}`,
            target: leftChildId,
            type: 'left'
          });

          if (2 * I + 1 < this.levels[L - 1].length) {
            const rightChildId = `L${L - 1}_I${2 * I + 1}`;
            links.push({
              id: `edge_L${L}_I${I}_to_${rightChildId}`,
              source: `L${L}_I${I}`,
              target: rightChildId,
              type: 'right'
            });
          }
        }
      }
    }

    return { nodes, links };
  }
}

// --- Static Verification functions ---

function decompInclProof(index, size) {
  const inner = index === size - 1 ? 0 : (index ^ (size - 1)).toString(2).length;
  const border = countOnes(index >> inner);
  return { inner, border };
}

function chainInner(seed, proof, index) {
  return proof.reduce((acc, h, i) => {
    if ((index >> i) & 1) {
      return Hasher.hashChildren(h, acc);
    } else {
      return Hasher.hashChildren(acc, h);
    }
  }, seed);
}

function chainInnerRight(seed, proof, index) {
  return proof.reduce((acc, h, i) => {
    if ((index >> i) & 1) {
      return Hasher.hashChildren(h, acc);
    }
    return acc;
  }, seed);
}

function chainBorderRight(seed, proof) {
  return proof.reduce((acc, h) => Hasher.hashChildren(h, acc), seed);
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Verify inclusion proof.
 * @param {number} index Leaf index
 * @param {number} size Tree size
 * @param {string|Uint8Array} leafValue Leaf raw value
 * @param {Array<Uint8Array>} proof Sibling hashes in the proof
 * @param {Uint8Array} root Expected root hash
 * @returns {boolean}
 */
export function verifyInclusion(index, size, leafValue, proof, root) {
  if (index >= size) return false;
  const leafBytes = typeof leafValue === 'string' ? stringToBytes(leafValue) : leafValue;
  const leafHash = Hasher.hashLeaf(leafBytes);

  const { inner, border } = decompInclProof(index, size);
  if (proof.length !== inner + border) return false;

  let hash = chainInner(leafHash, proof.slice(0, inner), index);
  hash = chainBorderRight(hash, proof.slice(inner));

  return arraysEqual(hash, root);
}

/**
 * Verify consistency proof.
 * @param {number} size1 Old tree size
 * @param {number} size2 New tree size
 * @param {Array<Uint8Array>} proof Proof hashes
 * @param {Uint8Array} root1 Old root hash
 * @param {Uint8Array} root2 New root hash
 * @returns {boolean}
 */
export function verifyConsistency(size1, size2, proof, root1, root2) {
  if (size2 < size1) return false;
  if (size1 === size2) {
    return proof.length === 0 && arraysEqual(root1, root2);
  }
  if (size1 === 0) {
    return proof.length === 0;
  }
  if (proof.length === 0) return false;

  const { inner, border } = decompInclProof(size1 - 1, size2);
  const shift = getTrailingZeros(size1);
  const adjustedInner = inner - shift;

  let seed = proof[0];
  let start = 1;
  if (size1 === (1 << shift)) {
    seed = root1;
    start = 0;
  }

  if (proof.length !== start + adjustedInner + border) return false;

  const activeProof = proof.slice(start);
  const mask = (size1 - 1) >> shift;

  // Verify first root
  let hash1 = chainInnerRight(seed, activeProof.slice(0, adjustedInner), mask);
  hash1 = chainBorderRight(hash1, activeProof.slice(adjustedInner));
  if (!arraysEqual(hash1, root1)) return false;

  // Verify second root
  let hash2 = chainInner(seed, activeProof.slice(0, adjustedInner), mask);
  hash2 = chainBorderRight(hash2, activeProof.slice(adjustedInner));
  return arraysEqual(hash2, root2);
}
