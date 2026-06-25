/**
 * Merkle Tree SVG Visualizer.
 * Renders Merkle trees and highlights proofs/paths.
 */

const SVG_NS = "http://www.w3.org/2000/svg";

export class MerkleVisualizer {
  /**
   * @param {SVGElement} svgElement The SVG container element
   * @param {Object} options Rendering options
   */
  constructor(svgElement, options = {}) {
    this.svg = svgElement;
    this.options = {
      nodeRadius: options.nodeRadius || 24,
      levelSpacing: options.levelSpacing || 80,
      nodeSpacing: options.nodeSpacing || 80,
      paddingX: options.paddingX || 50,
      paddingY: options.paddingY || 50,
      onLeafClick: options.onLeafClick || null,
      onNodeClick: options.onNodeClick || null,
      onNodeHover: options.onNodeHover || null,
    };
    this.tree = null;
    this.highlightState = null;
    this.coords = {}; // Maps node ID ("L{level}_I{index}") to {x, y}
  }

  /**
   * Render the Merkle Tree.
   * @param {MerkleTree} tree
   * @param {Object|null} highlightState e.g. { type: 'inclusion', leafIndex: 2 } or { type: 'consistency', size1: 3, size2: 4 }
   */
  render(tree, highlightState = null) {
    this.tree = tree;
    this.highlightState = highlightState;
    this.svg.innerHTML = ''; // Clear previous content
    this.coords = {};

    const visData = tree.getVisualizationData();
    if (visData.nodes.length === 0) return;

    // Calculate layout coordinates
    this.calculateLayout(visData.nodes);

    // Update SVG size
    this.updateSvgSize(visData.nodes);

    // Draw Edges (Lines) first so they are behind nodes
    this.drawEdges(visData.links);

    // Draw Nodes
    this.drawNodes(visData.nodes);
  }

  /**
   * Calculate coordinates for all nodes.
   */
  calculateLayout(nodes) {
    // Find max level
    const maxLevel = Math.max(...nodes.map(n => n.level));
    const leaves = nodes.filter(n => n.level === 0);
    
    // Sort leaves by index to lay them out sequentially
    leaves.sort((a, b) => a.index - b.index);

    // 1. Position leaves at level 0
    leaves.forEach((leaf, idx) => {
      this.coords[leaf.id] = {
        x: this.options.paddingX + idx * this.options.nodeSpacing,
        y: this.options.paddingY + maxLevel * this.options.levelSpacing
      };
    });

    // 2. Position parent levels bottom-up
    for (let L = 1; L <= maxLevel; L++) {
      const levelNodes = nodes.filter(n => n.level === L);
      levelNodes.forEach(node => {
        const leftChildId = `L${L - 1}_I${2 * node.index}`;
        const rightChildId = `L${L - 1}_I${2 * node.index + 1}`;
        
        const leftChildCoord = this.coords[leftChildId];
        const rightChildCoord = this.coords[rightChildId];

        let x = 0;
        if (leftChildCoord && rightChildCoord) {
          x = (leftChildCoord.x + rightChildCoord.x) / 2;
        } else if (leftChildCoord) {
          // Ephemeral node (carries over left child's coordinate)
          x = leftChildCoord.x;
        }

        this.coords[node.id] = {
          x: x,
          y: this.options.paddingY + (maxLevel - L) * this.options.levelSpacing
        };
      });
    }
  }

  updateSvgSize(nodes) {
    const coordsArray = Object.values(this.coords);
    const xs = coordsArray.map(c => c.x);
    const ys = coordsArray.map(c => c.y);

    const minX = Math.min(...xs) - this.options.nodeRadius - 20;
    const maxX = Math.max(...xs) + this.options.nodeRadius + 20;
    const minY = Math.min(...ys) - this.options.nodeRadius - 40;
    const maxY = Math.max(...ys) + this.options.nodeRadius + 40;

    const width = maxX - minX;
    const height = maxY - minY;

    this.svg.setAttribute('viewBox', `${minX} ${minY} ${width} ${height}`);
    this.svg.setAttribute('width', '100%');
    this.svg.setAttribute('height', height + 'px');
  }

  /**
   * Determine inclusion highlight classification for a node ID.
   * Returns: 'path', 'proof', or null
   */
  getInclusionHighlightClass(nodeId, leafIndex) {
    const size = this.tree.leaves.length;
    // We recreate the path and proof node sets
    const pathNodes = new Set();
    const proofNodes = new Set();

    let idx = leafIndex;
    for (let L = 0; L < this.tree.levels.length; L++) {
      pathNodes.add(`L${L}_I${idx}`);
      if (L < this.tree.levels.length - 1) {
        const siblingIdx = idx ^ 1;
        if (siblingIdx < this.tree.levels[L].length) {
          proofNodes.add(`L${L}_I${siblingIdx}`);
        }
      }
      idx = Math.floor(idx / 2);
    }

    if (pathNodes.has(nodeId)) return 'path';
    if (proofNodes.has(nodeId)) return 'proof';
    return null;
  }

  /**
   * Determine consistency highlight classification for a node ID.
   * Returns: 'old-root', 'proof', 'path-new', or null
   */
  getConsistencyHighlightClass(nodeId, size1, size2) {
    const trailingZeros = size1.toString(2).split('').reverse().indexOf('1');
    const level = trailingZeros >= 0 ? trailingZeros : 0;
    const index = (size1 - 1) >> level;

    // Get nodes from the consistency proof calculation
    const p = getProofNodesJs(index, level, size2);
    const ids = p.IDs;
    const startIdx = (index === 0) ? 1 : 0;

    const proofNodeIds = new Set();
    for (let i = startIdx; i < ids.length; i++) {
      proofNodeIds.add(`L${ids[i].level}_I${ids[i].index}`);
    }

    // Check if it is the old root (or roots)
    const oldRoots = getOldRootNodeIds(size1);
    const oldRootsSet = new Set(oldRoots);

    if (oldRootsSet.has(nodeId)) {
      return 'old-root';
    }
    if (proofNodeIds.has(nodeId)) {
      return 'proof';
    }
    return null;
  }

  getNodeState(node) {
    const { id } = node;
    let highlight = null;

    if (this.highlightState) {
      if (this.highlightState.type === 'inclusion') {
        highlight = this.getInclusionHighlightClass(id, this.highlightState.leafIndex);
      } else if (this.highlightState.type === 'consistency') {
        highlight = this.getConsistencyHighlightClass(id, this.highlightState.size1, this.highlightState.size2);
      } else if (this.highlightState.type === 'game') {
        highlight = this.highlightState.scannedNodes[id] || null;
      }
    }

    return highlight;
  }

  drawEdges(links) {
    links.forEach(link => {
      const parentCoord = this.coords[link.source];
      const childCoord = this.coords[link.target];
      if (!parentCoord || !childCoord) return;

      const line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('x1', parentCoord.x);
      line.setAttribute('y1', parentCoord.y);
      line.setAttribute('x2', childCoord.x);
      line.setAttribute('y2', childCoord.y);
      line.setAttribute('class', 'merkle-edge');

      // Determine highlight of the edge.
      // An edge is highlighted as 'path' if both source and target are 'path' nodes.
      // An edge is highlighted as 'proof-join' if target is a 'proof' node and source is a 'path' node.
      if (this.highlightState) {
        const sourceNode = { id: link.source };
        const targetNode = { id: link.target };
        const sourceState = this.getNodeState(sourceNode);
        const targetState = this.getNodeState(targetNode);

        if (sourceState === 'path' && targetState === 'path') {
          line.classList.add('edge-highlight-path');
        } else if (sourceState === 'path' && targetState === 'proof') {
          line.classList.add('edge-highlight-proof');
        } else if (sourceState === 'old-root' && targetState === 'old-root') {
          line.classList.add('edge-highlight-old-root');
        }
      }

      this.svg.appendChild(line);
    });
  }

  drawNodes(nodes) {
    nodes.forEach(node => {
      const coord = this.coords[node.id];
      if (!coord) return;

      const g = document.createElementNS(SVG_NS, 'g');
      g.setAttribute('class', 'merkle-node-group');
      g.setAttribute('id', `group_${node.id}`);

      // Add state classes
      if (node.isLeaf) g.classList.add('node-leaf');
      if (node.isEphemeral) g.classList.add('node-ephemeral');

      const highlight = this.getNodeState(node);
      if (highlight) {
        g.classList.add(`node-highlight-${highlight}`);
      }

      // Circle
      const circle = document.createElementNS(SVG_NS, 'circle');
      circle.setAttribute('cx', coord.x);
      circle.setAttribute('cy', coord.y);
      circle.setAttribute('r', this.options.nodeRadius);
      circle.setAttribute('class', 'merkle-node-circle');
      g.appendChild(circle);

      // Text: Coordinate/Index
      const coordText = document.createElementNS(SVG_NS, 'text');
      coordText.setAttribute('x', coord.x);
      coordText.setAttribute('y', coord.y - 4);
      coordText.setAttribute('class', 'merkle-node-coord');
      coordText.textContent = `L${node.level},I${node.index}`;
      g.appendChild(coordText);

      // Text: Short Hash
      const hashText = document.createElementNS(SVG_NS, 'text');
      hashText.setAttribute('x', coord.x);
      hashText.setAttribute('y', coord.y + 10);
      hashText.setAttribute('class', 'merkle-node-hash');
      hashText.textContent = node.shortHash;
      g.appendChild(hashText);

      // Label (For values of leaves or Root)
      if (node.isLeaf && node.value !== null) {
        const label = document.createElementNS(SVG_NS, 'text');
        label.setAttribute('x', coord.x);
        label.setAttribute('y', coord.y + this.options.nodeRadius + 18);
        label.setAttribute('class', 'merkle-node-label');
        label.textContent = node.value;
        g.appendChild(label);
      } else if (node.level === Math.max(...nodes.map(n => n.level)) && nodes.length > 1) {
        const label = document.createElementNS(SVG_NS, 'text');
        label.setAttribute('x', coord.x);
        label.setAttribute('y', coord.y - this.options.nodeRadius - 10);
        label.setAttribute('class', 'merkle-node-root-label');
        label.textContent = "Root Hash";
        g.appendChild(label);
      }

      // Event Handlers
      if (node.isLeaf && this.options.onLeafClick) {
        g.addEventListener('click', (e) => {
          // If we also have a node click, don't double fire
          if (this.options.onNodeClick) return;
          this.options.onLeafClick(node.index, node.value);
        });
      }

      if (this.options.onNodeClick) {
        g.addEventListener('click', () => {
          this.options.onNodeClick(node);
        });
      }

      if (this.options.onNodeHover) {
        g.addEventListener('mouseenter', () => {
          this.options.onNodeHover(node, coord);
        });
        g.addEventListener('mouseleave', () => {
          this.options.onNodeHover(null, null);
        });
      }

      this.svg.appendChild(g);
    });
  }
}

// --- Duplicate Helper Compact Math Functions to keep Visualizer independent of internal module scope ---

function decomposeJs(begin, end) {
  if (begin === 0) return [0, end];
  const xbegin = begin - 1;
  const xor = xbegin ^ end;
  const d = xor === 0 ? 0 : xor.toString(2).length - 1;
  const mask = (1 << d) - 1;
  return [(~xbegin) & mask, end & mask];
}

function getRangeNodesJs(begin, end) {
  const [left, right] = decomposeJs(begin, end);
  const ids = [];
  let pos = begin;
  let tempLeft = left;
  while (tempLeft !== 0) {
    const trailingZeros = tempLeft.toString(2).split('').reverse().indexOf('1');
    const level = trailingZeros >= 0 ? trailingZeros : 32;
    const bit = 1 << level;
    ids.push({ level, index: pos >> level });
    pos += bit;
    tempLeft ^= bit;
  }
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

function getProofNodesJs(index, level, size) {
  const xor = index ^ (size >> level);
  const inner = xor === 0 ? 0 : xor.toString(2).length - 1;
  const forkLevel = level + inner;
  const forkIndex = index >> inner;

  const fork = { level: forkLevel, index: forkIndex };
  const begin = forkIndex << forkLevel;
  const end = (forkIndex + 1) << forkLevel;

  const proof = [{ level, index }];
  let curr = { level, index };
  while (curr.level < fork.level) {
    const sibling = { level: curr.level, index: curr.index ^ 1 };
    proof.push(sibling);
    curr = { level: curr.level + 1, index: Math.floor(curr.index / 2) };
  }

  const rightNodes = getRangeNodesJs(end, size);
  rightNodes.reverse();
  proof.push(...rightNodes);

  const leftNodes = getRangeNodesJs(0, begin);
  leftNodes.reverse();
  proof.push(...leftNodes);

  return { IDs: proof };
}

/**
 * Returns list of Node IDs representing the root(s) of subtrees in a tree of size1.
 */
function getOldRootNodeIds(size1) {
  if (size1 <= 0) return [];
  // Decompose size1 into perfect subtrees
  const ids = [];
  let pos = 0;
  let remaining = size1;
  while (remaining !== 0) {
    const level = remaining.toString(2).length - 1;
    const bit = 1 << level;
    ids.push(`L${level}_I${pos >> level}`);
    pos += bit;
    remaining ^= bit;
  }
  return ids;
}
