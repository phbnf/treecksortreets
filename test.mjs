import { MerkleTree, verifyInclusion, verifyConsistency, bytesToHex, hexToBytes, Hasher } from './merkle.js';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function runTests() {
  console.log("Starting tests...");

  // Test 1: Empty Tree Root Hash
  const emptyTree = new MerkleTree();
  const emptyRoot = emptyTree.getRootHashHex();
  console.log("Empty tree root:", emptyRoot);
  assert(emptyRoot === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty root incorrect");

  // Test 2: Tree with 1 leaf
  const tree1 = new MerkleTree(["hello"]);
  const root1 = tree1.getRootHashHex();
  console.log("Tree of 1 leaf root:", root1);
  const expectedLeafHash = bytesToHex(Hasher.hashLeaf(new TextEncoder().encode("hello")));
  assert(root1 === expectedLeafHash, "Root of 1 leaf incorrect");

  // Test 3: Tree with 3 leaves and inclusion proof
  const leaves3 = ["apple", "banana", "cherry"];
  const tree3 = new MerkleTree(leaves3);
  const root3 = tree3.getRootHash();
  console.log("Tree of 3 leaves root:", bytesToHex(root3));

  for (let i = 0; i < 3; i++) {
    const proof = tree3.getInclusionProof(i);
    console.log(`Proof for leaf ${i} (${leaves3[i]}):`, proof.map(p => bytesToHex(p)));
    const ok = verifyInclusion(i, 3, leaves3[i], proof, root3);
    assert(ok, `Inclusion proof verification failed for leaf ${i}`);
  }

  // Test 4: Tree of 5 leaves and inclusion proof
  const leaves5 = ["A", "B", "C", "D", "E"];
  const tree5 = new MerkleTree(leaves5);
  const root5 = tree5.getRootHash();
  console.log("Tree of 5 leaves root:", bytesToHex(root5));

  for (let i = 0; i < 5; i++) {
    const proof = tree5.getInclusionProof(i);
    const ok = verifyInclusion(i, 5, leaves5[i], proof, root5);
    assert(ok, `Inclusion proof verification failed for leaf ${i} in tree of 5`);
  }

  // Test 5: Consistency proofs
  // We check consistency between all pairs of sizes from 1 to 8
  const allLeaves = ["1", "2", "3", "4", "5", "6", "7", "8"];
  const trees = [];
  for (let size = 0; size <= 8; size++) {
    trees[size] = new MerkleTree(allLeaves.slice(0, size));
  }

  for (let size1 = 1; size1 <= 8; size1++) {
    const root1 = trees[size1].getRootHash();
    for (let size2 = size1; size2 <= 8; size2++) {
      const root2 = trees[size2].getRootHash();
      // Generate consistency proof from tree of size2
      const proof = trees[size2].getConsistencyProof(size1, size2);
      const ok = verifyConsistency(size1, size2, proof, root1, root2);
      
      console.log(`Consistency proof size ${size1} -> ${size2}: [${proof.map(p => bytesToHex(p).substring(0, 6)).join(', ')}] - ${ok ? 'OK' : 'FAILED'}`);
      assert(ok, `Consistency proof failed between size ${size1} and ${size2}`);
    }
  }

  // Test 6: getVisualizationData structure
  const visData = tree3.getVisualizationData();
  console.log("Visualization nodes:", visData.nodes.map(n => `${n.id}(ephem=${n.isEphemeral}, val=${n.value}, hash=${n.shortHash})`));
  console.log("Visualization links:", visData.links.map(l => `${l.source} -> ${l.target}`));
  
  assert(visData.nodes.length === 6, "Expected 6 nodes for tree of size 3 (3 leaves + 2 level 1 nodes (one ephemeral) + 1 root)");
  assert(visData.links.length === 5, "Expected 5 links (2 from root to L1 nodes, 3 from L1 to L0 nodes)");

  console.log("All tests passed successfully!");
}

runTests();
