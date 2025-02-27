import { System } from "./types";
import { SCNavigationCore } from "./navCore";
import { CoordinateTransformer } from "./navPlanUtils";
import { ContainerType, getCoordinates, ObjectContainer, PointOfInterest, Vector3 } from "./types";

/**
 * Enhanced navigation node with improved metadata for bidirectional search
 */
export class NavNode {
    public position: Vector3;
    public parentNode: NavNode | null = null;
    public gCost: number = 0;        // Cost from start to this node
    public hCost: number = 0;        // Estimated cost from this node to goal
    public fCost: number = 0;        // Total cost (g + h)
    public type: 'origin' | 'destination' | 'om' | 'qt_marker' | 'intermediate';
    public name: string;
    public containerRef: ObjectContainer | null = null;
    public obstructionPath: boolean = false;  // Flag to indicate if this node is part of an obstruction avoidance path
    public searchDirection: 'forward' | 'backward' | 'both' = 'forward'; // Used for bidirectional search

    constructor(position: Vector3, type: 'origin' | 'destination' | 'om' | 'qt_marker' | 'intermediate', name: string, containerRef: ObjectContainer | null = null) {
        this.position = position;
        this.type = type;
        this.name = name;
        this.containerRef = containerRef;
    }

    // Calculate total cost
    public calculateFCost(): void {
        this.fCost = this.gCost + this.hCost;
    }

    // Create a deep clone of this node (useful for bidirectional search)
    public clone(): NavNode {
        const clone = new NavNode({ ...this.position }, this.type, this.name, this.containerRef);
        clone.gCost = this.gCost;
        clone.hCost = this.hCost;
        clone.fCost = this.fCost;
        clone.obstructionPath = this.obstructionPath;
        clone.searchDirection = this.searchDirection;
        return clone;
    }

    // Equality check based on position
    public equals(other: NavNode): boolean {
        return this.position.x === other.position.x &&
            this.position.y === other.position.y &&
            this.position.z === other.position.z;
    }
}

/**
 * Enhanced path segment with obstruction metadata
 */
export interface PathSegment {
    from: {
        name: string;
        position: Vector3;
        type: 'origin' | 'destination' | 'om' | 'qt_marker' | 'intermediate';
    };
    to: {
        name: string;
        position: Vector3;
        type: 'origin' | 'destination' | 'om' | 'qt_marker' | 'intermediate';
    };
    distance: number;
    travelType: 'quantum' | 'sublight';
    estimatedTime: number;
    direction: {
        pitch: number;
        yaw: number;
        roll: number;
    };
    obstruction: string | null; // Name of obstructing body if applicable
    isObstructionBypass: boolean; // Indicates if this segment exists to bypass an obstruction
}

/**
 * Enhanced navigation plan with detailed obstruction info
 */
export interface NavigationPlan {
    segments: PathSegment[];
    totalDistance: number;
    totalEstimatedTime: number;
    quantumJumps: number;
    obstructionDetected: boolean;
    obstructions: string[]; // Names of all obstructing bodies
    pathComplexity: 'direct' | 'simple' | 'complex'; // Indicates path complexity
    originContainer: ObjectContainer | null; // Origin reference frame
}

/**
 * Visibility graph edge for pre-computed visibility
 */
interface VisibilityEdge {
    fromNode: NavNode;
    toNode: NavNode;
    distance: number;
    hasLOS: boolean;
    obstruction: ObjectContainer | null;
}

/**
 * Meeting point between forward and backward searches
 */
export type MeetingPoint = {
    forwardNode: NavNode;
    backwardNode: NavNode;
    totalCost: number;
};

/**
 * Optimized Navigation Planner with bidirectional search and pre-computed visibility
 */
export class SCNavigationPlanner extends SCNavigationCore {
    // Navigation markers
    private orbitalMarkers: Map<string, NavNode[]> = new Map();
    private qtMarkers: NavNode[] = [];
    private allNavigationNodes: NavNode[] = [];

    // Precomputed visibility graph for efficient pathfinding
    private visibilityGraph: Map<string, VisibilityEdge[]> = new Map();

    // Maximum iterations for pathfinding (increased from original 100)
    private readonly MAX_ITERATIONS = 1000;

    // Current position reference frame
    private originContainer: ObjectContainer | null = null;

    constructor(poiData: PointOfInterest[], containerData: ObjectContainer[]) {
        super(poiData, containerData);
        this.initializeNavigationPoints();
        this.precomputeVisibilityGraph();
    }

    /**
     * Initialize all navigation points and build the node network
     */
    private initializeNavigationPoints(): void {
        // Generate orbital markers for each planet/moon
        this.containers.forEach(container => {
            if (container.cont_type === ContainerType.Planet || container.cont_type === ContainerType.Moon) {
                this.generateOrbitalMarkers(container);
            }
        });

        // Add quantum travel markers from POIs
        this.pois.forEach(poi => {
            if (poi.hasQTMarker) {
                const qtNode = new NavNode(
                    getCoordinates(poi, this.containers),
                    'qt_marker',
                    poi.name
                );
                this.qtMarkers.push(qtNode);
                this.allNavigationNodes.push(qtNode);
            }
        });

        // Add Lagrange points and Jump Points as QT markers
        this.containers.forEach(container => {
            if (container.cont_type === ContainerType.Lagrange || container.cont_type === ContainerType.JumpPoint) {
                const navNode = new NavNode(
                    { x: container.posX, y: container.posY, z: container.posZ },
                    'qt_marker',
                    container.name,
                    container
                );
                this.qtMarkers.push(navNode);
                this.allNavigationNodes.push(navNode);
            }
        });

        console.log(`Initialized ${this.allNavigationNodes.length} navigation nodes`);
        console.log(`- ${this.qtMarkers.length} QT markers`);
        console.log(`- ${this.orbitalMarkers.size} celestial bodies with orbital markers`);
    }

    /**
     * Generate orbital markers for a celestial body with optimized positioning
     */
    private generateOrbitalMarkers(container: ObjectContainer): void {
        const markers: NavNode[] = [];
        const radius = container.omRadius;
        const center: Vector3 = {
            x: container.posX,
            y: container.posY,
            z: container.posZ
        };

        // Create the 6 orbital markers positioned around the celestial body
        // OM-1: +z (North Pole)
        const om1 = new NavNode(
            { x: center.x, y: center.y, z: center.z + radius },
            'om',
            `${container.name} OM-1`,
            container
        );
        markers.push(om1);

        // OM-2: -z (South Pole)
        const om2 = new NavNode(
            { x: center.x, y: center.y, z: center.z - radius },
            'om',
            `${container.name} OM-2`,
            container
        );
        markers.push(om2);

        // OM-3: +y (East)
        const om3 = new NavNode(
            { x: center.x, y: center.y + radius, z: center.z },
            'om',
            `${container.name} OM-3`,
            container
        );
        markers.push(om3);

        // OM-4: -y (West)
        const om4 = new NavNode(
            { x: center.x, y: center.y - radius, z: center.z },
            'om',
            `${container.name} OM-4`,
            container
        );
        markers.push(om4);

        // OM-5: +x (North)
        const om5 = new NavNode(
            { x: center.x + radius, y: center.y, z: center.z },
            'om',
            `${container.name} OM-5`,
            container
        );
        markers.push(om5);

        // OM-6: -x (South)
        const om6 = new NavNode(
            { x: center.x - radius, y: center.y, z: center.z },
            'om',
            `${container.name} OM-6`,
            container
        );
        markers.push(om6);

        this.orbitalMarkers.set(container.name, markers);
        this.allNavigationNodes.push(...markers);
    }

    /**
     * Precompute visibility graph between all navigation nodes
     * This significantly improves pathfinding performance by avoiding redundant LOS checks
     */
    private precomputeVisibilityGraph(): void {
        // Initialize visibility graph with non-null assertion
        for (const node of this.allNavigationNodes) {
            this.visibilityGraph.set(this.getNodeKey(node), []);
        }

        // Compute visibility with explicit null checks
        for (let i = 0; i < this.allNavigationNodes.length; i++) {
            const fromNode = this.allNavigationNodes[i];
            // Type assertion to guarantee non-nullability - justified by array bounds check
            const fromKey = this.getNodeKey(fromNode!);

            for (let j = i + 1; j < this.allNavigationNodes.length; j++) {
                const toNode = this.allNavigationNodes[j];
                // Type assertion to guarantee non-nullability - justified by array bounds check
                const toKey = this.getNodeKey(toNode!);

                // Non-null assertions for property access
                if (fromNode!.type === 'om' && toNode!.type === 'om' &&
                    fromNode!.containerRef && toNode!.containerRef &&
                    fromNode!.containerRef.name === toNode!.containerRef.name) {
                    continue;
                }

                // Create bidirectional edges with type assertions
                const forwardEdge: VisibilityEdge = {
                    fromNode: fromNode!, // Non-null assertion
                    toNode: toNode!,     // Non-null assertion
                    distance: this.calcDistance3d(fromNode!.position, toNode!.position),
                    hasLOS: this.hasLineOfSight(fromNode!.position, toNode!.position).hasLos,
                    obstruction: this.hasLineOfSight(fromNode!.position, toNode!.position).obstruction
                };

                const backwardEdge: VisibilityEdge = {
                    fromNode: toNode!,   // Now safely typed
                    toNode: fromNode!,   // Now safely typed
                    distance: this.calcDistance3d(toNode!.position, fromNode!.position),
                    hasLOS: this.hasLineOfSight(toNode!.position, fromNode!.position).hasLos,
                    obstruction: this.hasLineOfSight(toNode!.position, fromNode!.position).obstruction
                };

                // Add edges to the graph
                this.visibilityGraph.get(fromKey)?.push(forwardEdge);
                this.visibilityGraph.get(toKey)?.push(backwardEdge);
            }
        }

        console.log(`Precomputed visibility graph with ${this.visibilityGraph.size} nodes`);
    }

    /**
     * Find all visible markers from a specific position using the precomputed visibility graph
     * @param position Current position
     * @param searchType Type of markers to search for ('all', 'orbital', 'qt')
     * @returns List of visible markers with obstruction information
     */
    private findVisibleMarkers(
        position: Vector3,
        searchType: 'all' | 'orbital' | 'qt' = 'all'
    ): { node: NavNode, obstruction: ObjectContainer | null }[] {
        const results: { node: NavNode, obstruction: ObjectContainer | null }[] = [];

        // Determine which nodes to check based on search type
        const nodesToCheck = searchType === 'all' ? this.allNavigationNodes :
            searchType === 'orbital' ? Array.from(this.orbitalMarkers.values()).flat() :
                this.qtMarkers;

        // Check visibility to each node
        for (const node of nodesToCheck) {
            const losResult = this.hasLineOfSight(position, node.position);
            if (losResult.hasLos) {
                results.push({ node, obstruction: null });
            } else {
                // Even if not visible, include with obstruction info for advanced pathfinding
                results.push({ node, obstruction: losResult.obstruction });
            }
        }

        return results;
    }

    /**
     * Bidirectional A* pathfinding algorithm optimized for 3D space navigation
     * This approach searches from both start and end simultaneously, which is
     * significantly more efficient for large 3D spaces with sparse connectivity
     */
    private findPathBidirectional(startPos: Vector3, endPos: Vector3): NavNode[] | null {
        // Log navigation parameters for debugging
        console.log(`Starting pathfinding:`);
        console.log(`- Origin: (${startPos.x.toFixed(2)}, ${startPos.y.toFixed(2)}, ${startPos.z.toFixed(2)})`);
        console.log(`- Destination: (${endPos.x.toFixed(2)}, ${endPos.y.toFixed(2)}, ${endPos.z.toFixed(2)})`);
        console.log(`- Direct distance: ${(this.calcDistance3d(startPos, endPos) / 1000).toFixed(2)} km`);

        // Create start and end nodes
        const startNode = new NavNode(startPos, 'origin', 'Start Position');
        startNode.searchDirection = 'forward';

        const endNode = new NavNode(endPos, 'destination', 'Destination');
        endNode.searchDirection = 'backward';

        // Check if there's a direct path
        const { hasLos, obstruction } = this.hasLineOfSight(startPos, endPos);
        if (hasLos) {
            // Direct path available - no changes needed
            console.log(`Direct path available - no obstructions detected`);
            const directPath = [startNode, endNode];
            endNode.parentNode = startNode;
            return directPath;
        } else if (obstruction) {
            console.log(`Direct path obstructed by ${obstruction.name}`);

            // ADDED: Explicitly handle obstruction with OM waypoints
            // Find the optimal OM for bypassing this obstruction
            const optimalOM = this.findOptimalOrbitalMarker(startPos, endPos, obstruction);
            console.log(`Selected ${optimalOM.name} for obstruction bypass`);

            // Find the orbital marker node in our navigation nodes
            const omNode = this.allNavigationNodes.find(node =>
                node.type === 'om' && node.name === optimalOM.name);

            if (omNode) {
                // Create an explicit path with the OM as an intermediate waypoint
                const bypassPath = [startNode, omNode.clone(), endNode];

                // Set parent relationships for path reconstruction
                omNode.parentNode = startNode;
                endNode.parentNode = omNode;

                // Mark the path as an obstruction bypass
                omNode.obstructionPath = true;

                console.log(`Created explicit obstruction bypass route via ${omNode.name}`);
                return bypassPath;
            }
        }

        // Initialize open and closed sets for bidirectional search
        const forwardOpenSet: NavNode[] = [startNode];
        const forwardClosedSet: NavNode[] = [];

        const backwardOpenSet: NavNode[] = [endNode];
        const backwardClosedSet: NavNode[] = [];

        // Tracking the best connection point between forward and backward searches
        let bestMeetingPoint: {
            value: MeetingPoint | null,
        } = {
            value: null,
        };

        // Find visible markers from start and end
        // Include even obstructed markers for advanced pathfinding
        console.log(`Finding visible navigation markers...`);
        const visibleFromStart = this.findVisibleMarkers(startPos);
        const visibleFromEnd = this.findVisibleMarkers(endPos);

        console.log(`- ${visibleFromStart.length} markers visible from start`);
        console.log(`- ${visibleFromEnd.length} markers visible from destination`);

        // Add visible markers to the open sets
        visibleFromStart.forEach(({ node, obstruction }) => {
            const newNode = node.clone();
            newNode.parentNode = startNode;
            newNode.gCost = this.calcDistance3d(startPos, newNode.position);
            newNode.hCost = this.calcDistance3d(newNode.position, endPos);
            newNode.calculateFCost();
            newNode.searchDirection = 'forward';
            newNode.obstructionPath = obstruction !== null;
            forwardOpenSet.push(newNode);
        });

        visibleFromEnd.forEach(({ node, obstruction }) => {
            const newNode = node.clone();
            newNode.parentNode = endNode;
            newNode.gCost = this.calcDistance3d(endPos, newNode.position);
            newNode.hCost = this.calcDistance3d(newNode.position, startPos);
            newNode.calculateFCost();
            newNode.searchDirection = 'backward';
            newNode.obstructionPath = obstruction !== null;
            backwardOpenSet.push(newNode);
        });

        // Maximum iterations tracker
        let iterations = 0;

        // Bidirectional A* algorithm
        console.log(`Starting bidirectional A* search...`);
        while (forwardOpenSet.length > 0 && backwardOpenSet.length > 0) {
            iterations++;
            if (iterations > this.MAX_ITERATIONS) {
                console.warn(`Reached maximum iterations (${this.MAX_ITERATIONS}) - stopping search`);
                break; // Safety limit to prevent infinite loops
            }

            // Process forward search
            this.processSearchDirection(
                forwardOpenSet,
                forwardClosedSet,
                backwardClosedSet,
                'forward',
                bestMeetingPoint
            );

            // Process backward search
            this.processSearchDirection(
                backwardOpenSet,
                backwardClosedSet,
                forwardClosedSet,
                'backward',
                bestMeetingPoint
            );

            // Check if we've found a meeting point
            if (bestMeetingPoint.value) {
                console.log(`Found optimal path after ${iterations} iterations`);
                // Reconstruct the bidirectional path
                return this.reconstructBidirectionalPath(
                    bestMeetingPoint.value.forwardNode,
                    bestMeetingPoint.value.backwardNode
                );
            }
        }

        // If we reach here, no path was found
        // Check if the search at least made progress and try to construct a partial path
        if (bestMeetingPoint.value) {
            console.log(`Found suboptimal path after ${iterations} iterations`);
            return this.reconstructBidirectionalPath(
                bestMeetingPoint.value.forwardNode,
                bestMeetingPoint.value.backwardNode
            );
        }

        console.error(`No path found after ${iterations} iterations`);
        // No viable path found
        return null;
    }

    /**
     * Process one iteration of search in the specified direction (forward or backward)
     */
    private processSearchDirection(
        openSet: NavNode[],
        closedSet: NavNode[],
        oppositeClosedSet: NavNode[],
        direction: 'forward' | 'backward',
        bestMeetingPoint: { value: MeetingPoint | null }
    ): void {
        if (openSet.length === 0) return;

        // Sort open set by fCost ascending
        openSet.sort((a, b) => a.fCost - b.fCost);

        // Get the node with the lowest fCost
        const currentNode = openSet.shift()!;

        // Move the current node to the closed set
        closedSet.push(currentNode);

        // Check for intersection with the opposite search direction
        for (const oppositeNode of oppositeClosedSet) {
            // Check if we can connect these nodes (direct line of sight)
            const { hasLos } = this.hasLineOfSight(currentNode.position, oppositeNode.position);

            if (hasLos) {
                // Calculate the total cost of this potential path
                const totalCost = currentNode.gCost +
                    oppositeNode.gCost +
                    this.calcDistance3d(currentNode.position, oppositeNode.position);

                // Update best meeting point if this is better
                if (!bestMeetingPoint.value || totalCost < bestMeetingPoint.value.totalCost) {
                    bestMeetingPoint.value = {
                        forwardNode: direction === 'forward' ? currentNode : oppositeNode,
                        backwardNode: direction === 'backward' ? currentNode : oppositeNode,
                        totalCost
                    };
                }
            }
        }

        // Find neighbors using the visibility graph
        const nodeKey = this.getNodeKey(currentNode);
        const visibleNeighbors = this.visibilityGraph.get(nodeKey) || [];

        for (const edge of visibleNeighbors) {
            // Skip if not a valid connection
            if (!edge.hasLOS) continue;

            const neighbor = edge.toNode.clone();
            neighbor.searchDirection = direction;

            // Skip if neighbor is in closed set
            if (closedSet.some(node => node.equals(neighbor))) {
                continue;
            }

            // Calculate tentative gCost
            const tentativeGCost = currentNode.gCost + edge.distance;

            // Check if neighbor is in open set
            const neighborInOpenSet = openSet.find(node => node.equals(neighbor));

            if (!neighborInOpenSet) {
                // Add neighbor to open set
                neighbor.parentNode = currentNode;
                neighbor.gCost = tentativeGCost;

                // Set hCost based on search direction
                if (direction === 'forward') {
                    neighbor.hCost = this.calcDistance3d(neighbor.position, bestMeetingPoint?.value?.backwardNode?.position || { x: 0, y: 0, z: 0 });
                } else {
                    neighbor.hCost = this.calcDistance3d(neighbor.position, bestMeetingPoint?.value?.forwardNode?.position || { x: 0, y: 0, z: 0 });
                }

                neighbor.calculateFCost();
                openSet.push(neighbor);
            } else if (tentativeGCost < neighborInOpenSet.gCost) {
                // Update neighbor's costs
                neighborInOpenSet.parentNode = currentNode;
                neighborInOpenSet.gCost = tentativeGCost;
                neighborInOpenSet.calculateFCost();
            }
        }
    }

    /**
     * Reconstruct a bidirectional path by joining forward and backward paths
     */
    private reconstructBidirectionalPath(forwardNode: NavNode, backwardNode: NavNode): NavNode[] {
        // Reconstruct the forward path
        const forwardPath: NavNode[] = [];
        let currentNode: NavNode | null = forwardNode;

        while (currentNode !== null) {
            forwardPath.unshift(currentNode);
            currentNode = currentNode.parentNode;
        }

        // Reconstruct the backward path
        const backwardPath: NavNode[] = [];
        currentNode = backwardNode;

        while (currentNode !== null) {
            backwardPath.push(currentNode);
            currentNode = currentNode.parentNode;
        }

        // Join the paths
        const completePath = [...forwardPath, ...backwardPath.slice(1)];
        console.log(`Reconstructed path with ${completePath.length} nodes`);

        return completePath;
    }

    /**
     * Calculate travel time with more realistic acceleration/deceleration curves
     */
    private calculateTravelTime(distance: number, travelType: 'quantum' | 'sublight'): number {
        if (travelType === 'quantum') {
            // Quantum travel velocity ~ 20% speed of light
            const speedOfLight = 299792458; // m/s
            const quantumSpeed = speedOfLight * 0.2; // m/s

            // Add acceleration/deceleration time (approximately 10 seconds each)
            const cruiseTime = distance / quantumSpeed;
            const transitionTime = 20; // seconds

            return cruiseTime + transitionTime;
        } else {
            // Sublight travel with acceleration model
            // Max speed ~ 1,000 m/s, acceleration ~ 50 m/s²
            const maxSpeed = 1000; // m/s
            const acceleration = 50; // m/s²

            // Time to reach full speed
            const timeToMaxSpeed = maxSpeed / acceleration;

            // Distance covered during acceleration/deceleration
            const accelDistance = 0.5 * acceleration * Math.pow(timeToMaxSpeed, 2);

            // Check if we have enough distance to reach max speed
            if (distance <= accelDistance * 2) {
                // Short distance - triangular velocity profile
                const peakTime = Math.sqrt(distance / acceleration);
                return peakTime * 2;
            } else {
                // Long distance - trapezoidal velocity profile
                const cruiseDistance = distance - (accelDistance * 2);
                const cruiseTime = cruiseDistance / maxSpeed;
                return (timeToMaxSpeed * 2) + cruiseTime;
            }
        }
    }

    /**
     * Create a detailed navigation plan from the path, including obstruction information
     */
    private createNavigationPlan(path: NavNode[]): NavigationPlan {
        const segments: PathSegment[] = [];

        let totalDistance = 0;
        let totalEstimatedTime = 0;
        let quantumJumps = 0;

        const obstructions: string[] = [];

        for (let i = 0; i < path.length - 1; i++) {
            const from = path[i];
            const to = path[i + 1];

            // Skip if either node is null/undefined
            if (!from || !to) continue;

            const distance = this.calcDistance3d(from.position, to.position);

            // Determine travel type based on distance and node types
            const useSublight =
                // Always use sublight when traveling to/from orbital markers
                from.type === 'om' || to.type === 'om'
                // Use sublight for short distances between non-OM nodes
                || distance <= 20000;

            const travelType: 'quantum' | 'sublight' =
                useSublight
                    ? 'sublight'
                    : 'quantum';

            // Calculate estimated time
            const estimatedTime = this.calculateTravelTime(distance, travelType);

            // Calculate direction
            const direction = this.calculateEulerAngles(from.position, to.position);

            // Check for obstructions in this segment
            const { obstruction } = this.hasLineOfSight(from.position, to.position);

            // Add obstruction to the list if found
            if (obstruction && !obstructions.includes(obstruction.name)) {
                obstructions.push(obstruction.name);
            }

            // Determine if this segment is part of an obstruction bypass
            const isObstructionBypass = from.obstructionPath || to.obstructionPath;

            // Create segment
            const segment: PathSegment = {
                from: {
                    name: from.name,
                    position: from.position,
                    type: from.type
                },
                to: {
                    name: to.name,
                    position: to.position,
                    type: to.type
                },
                distance,
                travelType,
                estimatedTime,
                direction,
                obstruction: obstruction?.name || null,
                isObstructionBypass
            };

            segments.push(segment);
            totalDistance += distance;
            totalEstimatedTime += estimatedTime;

            if (travelType === 'quantum') {
                quantumJumps++;
            }
        }

        // Determine path complexity
        let pathComplexity: 'direct' | 'simple' | 'complex';
        if (path.length === 2) {
            pathComplexity = 'direct';
        } else if (path.length <= 4) {
            pathComplexity = 'simple';
        } else {
            pathComplexity = 'complex';
        }

        return {
            segments,
            totalDistance,
            totalEstimatedTime,
            quantumJumps,
            obstructionDetected: obstructions.length > 0,
            obstructions,
            pathComplexity,
            originContainer: this.originContainer
        };
    }

    /**
     * Set current position using local coordinates relative to an object container
     * This provides deterministic positioning regardless of celestial rotation
     */
    public setPositionLocal(containerName: string, localX: number, localY: number, localZ: number): void {
        const container = this.containers.find(c => c.name === containerName);

        if (!container) {
            console.error(`Container ${containerName} not found`);
            return;
        }

        // Store reference to origin container for contextual navigation
        this.originContainer = container;

        // Transform local coordinates (in km) to global coordinates (in m)
        const globalPos = CoordinateTransformer.transformCoordinates(
            { x: localX, y: localY, z: localZ },
            container,
            'toGlobal'
        );

        // Update position with global coordinates
        this.updatePosition(globalPos.x, globalPos.y, globalPos.z);

        // Log position information
        console.log(`Position set: ${containerName} local (${localX.toFixed(3)}km, ${localY.toFixed(3)}km, ${localZ.toFixed(3)}km)`);
        console.log(`Global position: (${globalPos.x.toFixed(2)}, ${globalPos.y.toFixed(2)}, ${globalPos.z.toFixed(2)})`);

        // Log nearby POIs for context
        const nearbyPOIs = this.findNearbyPOIs(5);
        if (nearbyPOIs.length > 0) {
            console.log("Nearby references:");
            nearbyPOIs.forEach(poi => {
                console.log(`- ${poi.name}: ${poi.distance.toFixed(2)}km`);
            });
        }
    }

    /**
     * Update position and resolve to nearest container
     */
    public override updatePosition(x: number, y: number, z: number): void {
        super.updatePosition(x, y, z);

        // Update origin container if not set
        if (!this.originContainer) {
            this.originContainer = this.currentObjectContainer;
        }

        // Check if we have a current object container but no origin container, update it
        if (this.currentObjectContainer && !this.originContainer) {
            this.originContainer = this.currentObjectContainer;
        }
    }

    /**
     * Find nearby Points of Interest for contextual awareness
     * @returns Array of POIs with distances
     */
    public findNearbyPOIs(limit: number = 3): Array<{ name: string, distance: number }> {
        if (!this.currentPosition) {
            return [];
        }

        return this.pois
            .map(poi => {
                const poiCoords = getCoordinates(poi, this.containers);
                return {
                    name: poi.name,
                    distance: this.calcDistance3d(this.currentPosition!, poiCoords) / 1000 // Convert to km
                };
            })
            .sort((a, b) => a.distance - b.distance)
            .slice(0, limit);
    }

    /**
     * Generate a unique key for a navigation node for graph operations
     */
    private getNodeKey(node: NavNode): string {
        if (!node) {
            throw new Error("Node reference is null during key generation");
        }

        return `${node.type}_${node.position.x.toFixed(3)}_${node.position.y.toFixed(3)}_${node.position.z.toFixed(3)}`;
    }

    /**
     * Check if there's a direct line of sight between two positions
     * Performs ray casting against celestial body collision geometry
     */
    private hasLineOfSight(from: Vector3, to: Vector3): { hasLos: boolean, obstruction: ObjectContainer | null } {
        // Vector between positions
        const dx = to.x - from.x;
        const dy = to.y - from.y;
        const dz = to.z - from.z;

        // Distance between points
        const distance = Math.sqrt(dx * dx + dy * dy + dz * dz);

        // Direction vector (normalized)
        const dirX = dx / distance;
        const dirY = dy / distance;
        const dirZ = dz / distance;

        // Check each celestial body for intersection
        for (const body of this.containers) {
            // Skip non-physical objects
            if (!body.bodyRadius || body.bodyRadius <= 0) continue;

            // Skip bodies that are in the Pyro system when in Stanton (and vice versa)
            // This prevents incorrect obstruction detection across star systems
            if (body.system && this.currentObjectContainer?.system && body.system !== this.currentObjectContainer.system) {
                continue;
            }

            // Vector from origin to sphere center
            const ocX = body.posX - from.x;
            const ocY = body.posY - from.y;
            const ocZ = body.posZ - from.z;

            // Projection of oc onto the ray direction
            const projOc = ocX * dirX + ocY * dirY + ocZ * dirZ;

            // If negative, sphere is behind the ray origin
            if (projOc < 0 && (ocX * ocX + ocY * ocY + ocZ * ocZ) > body.bodyRadius * body.bodyRadius) continue;

            // Squared distance from sphere center to ray
            const distSq = (ocX * ocX + ocY * ocY + ocZ * ocZ) - (projOc * projOc);
            const radiusSq = body.bodyRadius * body.bodyRadius;

            // If this distance > radius, no intersection
            if (distSq > radiusSq) continue;

            // Distance from projection to intersection points
            const intersectDist = Math.sqrt(radiusSq - distSq);

            // Calculate first intersection distance
            const intersect1 = projOc - intersectDist;
            const intersect2 = projOc + intersectDist;

            // If either intersection point is within our segment length, we have obstruction
            if ((intersect1 > 0 && intersect1 < distance) ||
                (intersect2 > 0 && intersect2 < distance)) {
                return { hasLos: false, obstruction: body };
            }
        }

        // No obstructions found
        return { hasLos: true, obstruction: null };
    }

    /**
     * Get the optimal orbital marker to navigate around an obstruction
     */
    private findOptimalOrbitalMarker(
        start: Vector3,
        end: Vector3,
        obstruction: ObjectContainer
    ): { name: string, position: Vector3 } {
        // Get all orbital markers for this body
        const markers = this.orbitalMarkers.get(obstruction.name) || [];

        // Fallback if no markers found
        if (markers.length === 0) {
            return {
                name: `${obstruction.name} vicinity`,
                position: {
                    x: obstruction.posX + obstruction.omRadius,
                    y: obstruction.posY,
                    z: obstruction.posZ
                }
            };
        }

        // Calculate vectors
        const startToObstruction = {
            x: obstruction.posX - start.x,
            y: obstruction.posY - start.y,
            z: obstruction.posZ - start.z
        };

        const obstructionToEnd = {
            x: end.x - obstruction.posX,
            y: end.y - obstruction.posY,
            z: end.z - obstruction.posZ
        };

        // Initialize with first marker - guaranteed non-null due to length check above
        let bestMarker: NavNode = markers[0]!;
        let bestScore = -Infinity;

        // Normalize vectors
        const startMag = Math.sqrt(
            startToObstruction.x * startToObstruction.x +
            startToObstruction.y * startToObstruction.y +
            startToObstruction.z * startToObstruction.z
        );

        const endMag = Math.sqrt(
            obstructionToEnd.x * obstructionToEnd.x +
            obstructionToEnd.y * obstructionToEnd.y +
            obstructionToEnd.z * obstructionToEnd.z
        );

        const normalized1 = {
            x: startToObstruction.x / startMag,
            y: startToObstruction.y / startMag,
            z: startToObstruction.z / startMag
        };

        const normalized2 = {
            x: obstructionToEnd.x / endMag,
            y: obstructionToEnd.y / endMag,
            z: obstructionToEnd.z / endMag
        };

        // Calculate cross product to determine optimal orbital plane
        const crossProduct = {
            x: normalized1.y * normalized2.z - normalized1.z * normalized2.y,
            y: normalized1.z * normalized2.x - normalized1.x * normalized2.z,
            z: normalized1.x * normalized2.y - normalized1.y * normalized2.x
        };

        markers.forEach(marker => {
            // Get marker vector from obstruction center
            const markerVector = {
                x: marker.position.x - obstruction.posX,
                y: marker.position.y - obstruction.posY,
                z: marker.position.z - obstruction.posZ
            };

            // Calculate dot product with cross product to find alignment
            const alignmentScore =
                markerVector.x * crossProduct.x +
                markerVector.y * crossProduct.y +
                markerVector.z * crossProduct.z;

            if (Math.abs(alignmentScore) > Math.abs(bestScore)) {
                bestScore = alignmentScore;
                bestMarker = marker;
            }
        });

        // TypeScript assertion not needed here - bestMarker is guaranteed to be defined
        // because we initialized it with markers[0] and markers.length > 0
        return {
            name: bestMarker.name,
            position: bestMarker.position
        };
    }

    /**
     * Helper method for calculating distance between two positions
     */
    private calcDistance3dFromPositions(p1: Vector3, p2: Vector3): number {
        return Math.sqrt(
            Math.pow(p1.x - p2.x, 2) +
            Math.pow(p1.y - p2.y, 2) +
            Math.pow(p1.z - p2.z, 2)
        );
    }

    /**
     * Find the parent planet of a moon
     */
    private findParentPlanet(
        moon: ObjectContainer,
        planets: ObjectContainer[],
    ): ObjectContainer | null {
        // Try to infer parent planet from naming patterns
        const moonName = moon.name.toLowerCase();

        for (const planet of planets) {
            const planetName = planet.name.toLowerCase();
            if (moonName.includes(planetName)) {
                return planet;
            }
        }

        // Default to closest planet by distance
        let closestPlanet = null;
        let minDistance = Number.MAX_VALUE;

        for (const planet of planets) {
            const distance = this.calcDistance3dFromPositions(
                { x: moon.posX, y: moon.posY, z: moon.posZ },
                { x: planet.posX, y: planet.posY, z: planet.posZ }
            );

            if (distance < minDistance) {
                minDistance = distance;
                closestPlanet = planet;
            }
        }

        return closestPlanet;
    }

    /**
     * Determines if a destination requires going through its parent planet first
     * Properly handles the complete celestial hierarchy for multi-body traversal
     * 
     * @param destination The POI or container being navigated to
     * @param currentContainer The current container the player is in
     * @returns Whether planetary intercept is required and the parent container if applicable
     */
    private requiresPlanetaryIntercept(
        destination: PointOfInterest | ObjectContainer,
        currentContainer: ObjectContainer | null
    ): { required: boolean; parentContainer: ObjectContainer | null } {
        // If no current container, we're in open space and need to approach any planetary body
        if (!currentContainer) {
            // If destination is or is on a celestial body, we need to approach it
            const destContainer = 'objContainer' in destination
                ? this.containers.find(c => c.name === destination.objContainer)
                : ('cont_type' in destination ? destination : null);

            return {
                required: !!destContainer,
                parentContainer: destContainer || null
            };
        }

        // Determine destination container
        const destContainer = 'objContainer' in destination
            ? this.containers.find(c => c.name === destination.objContainer)
            : ('cont_type' in destination ? destination : null);

        // If we're already at the correct container, no intercept needed
        if (destContainer && destContainer.name === currentContainer.name) {
            return { required: false, parentContainer: null };
        }

        // Find parent planet of current container (if applicable)
        const currentIsOnPlanet = currentContainer.cont_type === ContainerType.Planet;
        const currentIsOnMoon = currentContainer.cont_type === ContainerType.Moon;
        const currentParentPlanet = currentIsOnMoon
            ? this.findParentPlanet(currentContainer, this.containers)
            : (currentIsOnPlanet ? currentContainer : null);

        // Find parent planet of destination (if applicable)
        const destIsOnPlanet = destContainer && destContainer.cont_type === ContainerType.Planet;
        const destIsOnMoon = destContainer && destContainer.cont_type === ContainerType.Moon;
        const destParentPlanet = destIsOnMoon && destContainer
            ? this.findParentPlanet(destContainer, this.containers)
            : (destIsOnPlanet && destContainer ? destContainer : null);

        console.log(`Analyzing planetary hierarchy:`);
        console.log(`- Current: ${currentContainer.name} (${currentContainer.cont_type})`);
        if (currentParentPlanet) console.log(`  Parent: ${currentParentPlanet.name}`);
        console.log(`- Destination: ${destContainer ? destContainer.name : 'None'} (${destContainer ? destContainer.cont_type : 'None'})`);
        if (destParentPlanet) console.log(`  Parent: ${destParentPlanet.name}`);

        // Case 1: If current and destination parent planets are different
        if (currentParentPlanet && destParentPlanet &&
            currentParentPlanet.name !== destParentPlanet.name) {
            console.log(`Planetary intercept required: Must approach ${destParentPlanet.name} first`);
            return { required: true, parentContainer: destParentPlanet };
        }

        // Case 2: If we're on a planet/moon and destination is on a different planet/moon
        if ((currentIsOnPlanet || currentIsOnMoon) &&
            destContainer &&
            destContainer.name !== currentContainer.name) {
            // If destination is a moon, need to go through its parent planet first
            if (destIsOnMoon && destParentPlanet) {
                console.log(`Moon intercept required: Must approach ${destParentPlanet.name} first, then ${destContainer.name}`);
                return { required: true, parentContainer: destParentPlanet };
            }

            // If destination is a planet, go directly to it
            if (destIsOnPlanet) {
                console.log(`Planet intercept required: Direct approach to ${destContainer.name}`);
                return { required: true, parentContainer: destContainer };
            }
        }

        // Default: No special intercept required
        return { required: false, parentContainer: null };
    }

    /**
     * Creates a navigational route with proper planetary intercepts
     * Handles multi-step approaches through parent planets when required
     * 
     * @param startPos Origin position in global coordinates
     * @param endPos Destination position in global coordinates
     * @param destination The destination entity
     * @returns A properly structured navigation path 
     */
    private createHierarchicalPlanetaryRoute(
        startPos: Vector3,
        endPos: Vector3,
        destination: PointOfInterest | ObjectContainer
    ): NavNode[] {
        // Normalize coordinates to ensure consistent space
        startPos = this.ensureGlobalCoordinates(startPos, this.currentObjectContainer);
        
        // Get destination container reference for coordinate normalization
        const destContainer = 'objContainer' in destination ? 
            this.containers.find(c => c.name === destination.objContainer) : 
            ('cont_type' in destination ? destination : null);
        
        endPos = this.ensureGlobalCoordinates(endPos, destContainer);
        
        // Start with origin node
        const startNode = new NavNode(
            startPos,
            'origin',
            'Start Position'
        );

        // Find current container
        const currentContainer = this.currentObjectContainer;
        
        // Check if planetary intercept is required
        const { required: interceptRequired, parentContainer: primaryIntercept } =
            this.requiresPlanetaryIntercept(
                destination,
                currentContainer
            );

        // If no intercept required, return direct path
        if (!interceptRequired || !primaryIntercept) {
            const endNode = new NavNode(
                endPos,
                'destination',
                'objContainer' in destination ? destination.name : destination.name
            );
            endNode.parentNode = startNode;
            return [startNode, endNode];
        }

        // Create an array to build our route
        const routeNodes: NavNode[] = [startNode];
        
        // Calculate primary intercept
        const primaryInterceptPoint = this.calculatePlanetaryIntercept(
            startPos,
            primaryIntercept.posX ? 
                { x: primaryIntercept.posX, y: primaryIntercept.posY, z: primaryIntercept.posZ } : 
                endPos,
            primaryIntercept
        );
        
        // Add primary intercept node
        const primaryInterceptNode = new NavNode(
            primaryInterceptPoint,
            'intermediate',
            `${primaryIntercept.name} Approach Vector`,
            primaryIntercept
        );
        primaryInterceptNode.parentNode = startNode;
        routeNodes.push(primaryInterceptNode);
        
        // Check if we need a secondary intercept (for moon destinations)
        const needsSecondaryIntercept = 
            destContainer && 
            destContainer.cont_type === ContainerType.Moon && 
            primaryIntercept.name !== destContainer.name;
        
        if (needsSecondaryIntercept && destContainer) {
            console.log(`Adding secondary intercept through ${destContainer.name}`);
            // Calculate secondary intercept point
            const secondaryInterceptPoint = this.calculatePlanetaryIntercept(
                primaryInterceptPoint,
                endPos,
                destContainer
            );
            
            // Add secondary intercept node
            const secondaryInterceptNode = new NavNode(
                secondaryInterceptPoint,
                'intermediate',
                `${destContainer.name} Approach Vector`,
                destContainer
            );
            secondaryInterceptNode.parentNode = primaryInterceptNode;
            routeNodes.push(secondaryInterceptNode);
            
            // Add final destination
            const endNode = new NavNode(
                endPos,
                'destination',
                'objContainer' in destination ? destination.name : destination.name
            );
            endNode.parentNode = secondaryInterceptNode;
            routeNodes.push(endNode);
        } else {
            // Add final destination directly
            const endNode = new NavNode(
                endPos,
                'destination',
                'objContainer' in destination ? destination.name : destination.name
            );
            endNode.parentNode = primaryInterceptNode;
            routeNodes.push(endNode);
        }
        
        return routeNodes;
    }

    /**
     * Calculate the optimal intercept point on a planet's surface
     * Ensures all coordinates are properly transformed to global space
     * 
     * @param startPos Origin position in global coordinates
     * @param endPos Destination position in global coordinates
     * @param planet The planet to intercept
     * @returns Optimal intercept coordinates on planet's sphere in global space
     */
    private calculatePlanetaryIntercept(
        startPos: Vector3,
        endPos: Vector3,
        planet: ObjectContainer
    ): Vector3 {
        // Normalize input coordinates
        startPos = this.ensureGlobalCoordinates(startPos);
        endPos = this.ensureGlobalCoordinates(endPos);
        
        // Ensure planet has valid coordinates
        if (!planet.posX && planet.posX !== 0) {
            console.error(`Invalid planet coordinates for ${planet.name}`);
            // Return a fallback position
            return startPos;
        }

        // Vector from planet center to start position
        const startVec = {
            x: startPos.x - planet.posX,
            y: startPos.y - planet.posY,
            z: startPos.z - planet.posZ
        };

        // Normalize start vector
        const startMag = Math.sqrt(
            startVec.x * startVec.x +
            startVec.y * startVec.y +
            startVec.z * startVec.z
        );

        // Safety check to prevent division by zero
        if (startMag < 0.001) {
            console.warn(`Near-zero magnitude for approach vector to ${planet.name}`);
            // Create a fallback intercept vector
            return {
                x: planet.posX + planet.omRadius * 0.7071, // sqrt(2)/2
                y: planet.posY + planet.omRadius * 0.7071,
                z: planet.posZ
            };
        }

        // Use standard OM radius or a reasonable multiple of bodyRadius if omRadius isn't available
        const interceptRadius = planet.omRadius || (planet.bodyRadius * 1.5);

        // Vector from planet center to end position
        const endVec = {
            x: endPos.x - planet.posX,
            y: endPos.y - planet.posY,
            z: endPos.z - planet.posZ
        };

        // Normalize vectors
        const endMag = Math.sqrt(
            endVec.x * endVec.x +
            endVec.y * endVec.y +
            endVec.z * endVec.z
        );

        // Calculate weighted approach vector for optimal interception
        // Weight toward start vector but consider end direction
        const approachVec = {
            x: (startVec.x / startMag * 0.7) + (endVec.x / endMag * 0.3),
            y: (startVec.y / startMag * 0.7) + (endVec.y / endMag * 0.3),
            z: (startVec.z / startMag * 0.7) + (endVec.z / endMag * 0.3)
        };

        // Normalize approach vector
        const approachMag = Math.sqrt(
            approachVec.x * approachVec.x +
            approachVec.y * approachVec.y +
            approachVec.z * approachVec.z
        );

        // Calculate optimal intercept using the weighted approach
        const interceptPoint: Vector3 = {
            x: planet.posX + (approachVec.x / approachMag) * interceptRadius,
            y: planet.posY + (approachVec.y / approachMag) * interceptRadius,
            z: planet.posZ + (approachVec.z / approachMag) * interceptRadius
        };

        console.log(`Calculated intercept for ${planet.name} at (${interceptPoint.x.toFixed(2)}, ${interceptPoint.y.toFixed(2)}, ${interceptPoint.z.toFixed(2)})`);
        return interceptPoint;
    }

    /**
     * Plan navigation with improved system boundary enforcement and hierarchical routing
     * @param destinationName Name of the destination point of interest or container
     * @returns Complete navigation plan or null if route cannot be established
     */
    public planNavigation(destinationName: string): NavigationPlan | null {
        if (!this.currentPosition) {
            console.error("Navigation origin undefined: position telemetry unavailable");
            return null;
        }

        // Destination coordinate resolution
        let destinationPos: Vector3 | null = null;
        let destinationSystem: string = "Stanton";
        let destinationEntity: PointOfInterest | ObjectContainer | null = null;

        // POI entity resolution
        const poiDestination = this.pois.find(poi => poi.name === destinationName);
        if (poiDestination) {
            destinationPos = getCoordinates(poiDestination, this.containers);
            destinationSystem = poiDestination.system;
            destinationEntity = poiDestination;
        }

        // Container entity resolution
        if (!destinationPos) {
            const containerDestination = this.containers.find(container => container.name === destinationName);
            if (containerDestination) {
                destinationPos = {
                    x: containerDestination.posX,
                    y: containerDestination.posY,
                    z: containerDestination.posZ
                };
                destinationSystem = containerDestination.system;
                destinationEntity = containerDestination;
            }
        }

        if (!destinationPos || !destinationEntity) {
            console.error(`Destination entity '${destinationName}' not found in astronomical database`);
            return null;
        }

        // Origin system determination
        const originSystem = this.currentObjectContainer?.system || System.Stanton;

        // Cross-system routing validation
        if (destinationSystem && originSystem !== destinationSystem) {
            console.error(`Interstellar routing prohibited: ${originSystem} → ${destinationSystem}`);
            return null;
        }

        // Normalize destination coordinates to global space
        destinationPos = this.ensureGlobalCoordinates(destinationPos, 
            'objContainer' in destinationEntity ? 
            this.containers.find(c => c.name === destinationEntity.objContainer) : null);

        console.log(`Planning route to ${destinationName} in ${destinationSystem} system`);
        console.log(`Destination coordinates: (${destinationPos.x.toFixed(2)}, ${destinationPos.y.toFixed(2)}, ${destinationPos.z.toFixed(2)})`);

        // Create hierarchical planetary route with proper intercepts
        const path = this.createHierarchicalPlanetaryRoute(
            this.currentPosition,
            destinationPos,
            destinationEntity
        );

        // Navigation plan synthesis
        return this.createNavigationPlan(path);
    }

    /**
     * Ensures a position is in global coordinate space (meters)
     * Performs necessary conversions if the position appears to be in local space
     * 
     * @param position Position vector to normalize
     * @param container Optional reference container for local-to-global conversion
     * @returns Position vector in global coordinate space
     */
    private ensureGlobalCoordinates(position: Vector3, container?: ObjectContainer | null): Vector3 {
        // Handle null/undefined case
        if (!position) {
            console.error("Null position vector encountered during coordinate normalization");
            return { x: 0, y: 0, z: 0 };
        }
        
        // Heuristic to detect if position is in local space (kilometers)
        // Local coordinates are typically small (< 10000 km) 
        // Typical orbital bodies have coordinates in the 10^9-10^12 range in global space
        const isProbablyLocalSpace = 
            Math.abs(position.x) < 10000 && 
            Math.abs(position.y) < 10000 && 
            Math.abs(position.z) < 10000 &&
            // Only consider it local if we have a reference container
            container !== undefined && 
            container !== null;
        
        // If position is likely in local space and we have a container, convert to global
        if (isProbablyLocalSpace && container) {
            console.log(`Converting suspected local coordinates to global for ${container.name}`);
            return CoordinateTransformer.transformCoordinates(
                position,
                container,
                'toGlobal'
            );
        }
        
        // Otherwise, return as is
        return { ...position };  // Return a copy to avoid mutation
    }

    /**
     * Format the navigation plan as human-readable instructions with enhanced details
     */
    public formatNavigationInstructions(plan: NavigationPlan): string {
        if (!plan || plan.segments.length === 0) {
            return "No valid navigation plan available.";
        }

        let instructions = "NAVIGATION PLAN\n";
        instructions += "===============\n\n";

        // Add origin reference if available
        if (plan.originContainer) {
            instructions += `ORIGIN: ${plan.originContainer.name}\n\n`;
        }

        if (plan.obstructionDetected) {
            instructions += "⚠️ OBSTRUCTIONS DETECTED:\n";
            instructions += `Celestial bodies blocking direct path: ${plan.obstructions.join(', ')}\n`;
            instructions += `Multiple jumps required (${plan.segments.length} segments, ${plan.quantumJumps} quantum jumps)\n\n`;

            // Add specific obstruction handling instructions
            instructions += "OBSTRUCTION MITIGATION PLAN:\n";

            plan.obstructions.forEach(obstruction => {
                const obstructingBody = this.containers.find(c => c.name === obstruction);

                if (obstructingBody && this.currentPosition && plan.segments.length > 0) {
                    // Find the optimal OM to use for navigation around this body
                    // Safely access the last segment
                    const lastSegment = plan.segments[plan.segments.length - 1];
                    if (lastSegment && lastSegment.to) {
                        const optimalOM = this.findOptimalOrbitalMarker(
                            this.currentPosition,
                            lastSegment.to.position,
                            obstructingBody
                        );

                        instructions += `- To navigate around ${obstruction}, route via ${optimalOM.name}.\n`;
                        instructions += `  Set HUD marker to ${optimalOM.name} first, then to final destination.\n`;
                    }
                }
            });

            instructions += "\n";
        } else {
            instructions += "✓ CLEAR PATH AVAILABLE: Direct route possible.\n\n";
        }

        instructions += `Total Distance: ${(plan.totalDistance / 1000).toFixed(2)} km\n`;

        // Format time nicely
        const hours = Math.floor(plan.totalEstimatedTime / 3600);
        const minutes = Math.floor((plan.totalEstimatedTime % 3600) / 60);
        const seconds = Math.floor(plan.totalEstimatedTime % 60);
        let timeString = "";

        if (hours > 0) {
            timeString += `${hours}h `;
        }
        if (minutes > 0 || hours > 0) {
            timeString += `${minutes}m `;
        }
        timeString += `${seconds}s`;

        instructions += `Estimated Travel Time: ${timeString}\n`;
        instructions += `Path Complexity: ${plan.pathComplexity.toUpperCase()}\n\n`;
        instructions += "ROUTE SEGMENTS:\n";

        // Format each segment
        plan.segments.forEach((segment, index) => {
            instructions += `\n[${index + 1}] ${segment.from.name} → ${segment.to.name}\n`;

            // Add obstruction bypass indicator if applicable
            if (segment.isObstructionBypass) {
                instructions += `    ↳ OBSTRUCTION BYPASS SEGMENT\n`;
            }

            instructions += `    Distance: ${(segment.distance / 1000).toFixed(2)} km\n`;
            instructions += `    Travel Mode: ${segment.travelType === 'quantum' ? 'QUANTUM TRAVEL' : 'SUBLIGHT'}\n`;

            // Format time for this segment
            const segHours = Math.floor(segment.estimatedTime / 3600);
            const segMinutes = Math.floor((segment.estimatedTime % 3600) / 60);
            const segSeconds = Math.floor(segment.estimatedTime % 60);
            let segTimeString = "";

            if (segHours > 0) {
                segTimeString += `${segHours}h `;
            }
            if (segMinutes > 0 || segHours > 0) {
                segTimeString += `${segMinutes}m `;
            }
            segTimeString += `${segSeconds}s`;

            instructions += `    Time: ${segTimeString}\n`;

            // For quantum travel, provide orientation instructions
            if (segment.travelType === 'quantum') {
                instructions += `    Align: Pitch ${segment.direction.pitch.toFixed(1)}°, Yaw ${segment.direction.yaw.toFixed(1)}°\n`;
            }

            // Add obstruction information if applicable
            if (segment.obstruction) {
                instructions += `    ⚠️ CAUTION: ${segment.obstruction} may obstruct direct visual on destination\n`;
            }
        });

        return instructions;
    }

    /**
     * Determine current solar system with robust cross-system detection
     */
    public determineCurrentSolarSystem(
        plan: NavigationPlan | null = null,
    ): System {
        if (plan === null) {
            if (this.currentObjectContainer) {
                return this.currentObjectContainer.system;
            }
            return System.Stanton;
        }

        // Primary directive: Extract system from container metadata
        if (plan.originContainer && plan.originContainer.system) {
            return plan.originContainer.system;
        }

        // Tertiary analysis: Route segment inspection
        if (plan.segments && plan.segments.length > 0) {
            // Extract terminal node metadata
            const firstSegment = plan.segments[0];
            const lastSegment = plan.segments[plan.segments.length - 1];

            if (firstSegment && firstSegment.from && firstSegment.from.name) {
                // Container entity resolution
                const originContainer = this.containers.find(c => c.name === firstSegment.from.name);

                if (originContainer && originContainer.system) {
                    return originContainer.system;
                }
            }

            // Destination analysis fallback
            if (lastSegment && lastSegment.to && lastSegment.to.name) {
                const destContainer = this.containers.find(c => c.name === lastSegment.to.name);

                if (destContainer && destContainer.system) {
                    return destContainer.system;
                }
            }
        }

        console.warn("Celestial domain resolution failed: defaulting to Stanton system");
        return System.Stanton;
    }
}