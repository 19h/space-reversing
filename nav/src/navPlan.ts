import { SCNavigationCore } from "./navCore";
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
        const clone = new NavNode({...this.position}, this.type, this.name, this.containerRef);
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
    private readonly MAX_ITERATIONS = 500;
    
    // Coordinate transformation cache to optimize repeat calculations
    private coordTransformCache: Map<string, Vector3> = new Map();

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
                    getCoordinates(poi),
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
        // Initialize visibility graph
        for (const node of this.allNavigationNodes) {
            this.visibilityGraph.set(this.getNodeKey(node), []);
        }

        // Compute visibility between all node pairs
        // This is O(n²) but only done once at initialization
        for (let i = 0; i < this.allNavigationNodes.length; i++) {
            const fromNode = this.allNavigationNodes[i];
            const fromKey = this.getNodeKey(fromNode);

            for (let j = i + 1; j < this.allNavigationNodes.length; j++) {
                const toNode = this.allNavigationNodes[j];
                const toKey = this.getNodeKey(toNode);

                // Skip if nodes are from the same celestial body's orbital markers
                // (Optimization: orbital markers of the same body don't always have direct LOS)
                if (fromNode.type === 'om' && toNode.type === 'om' && 
                    fromNode.containerRef && toNode.containerRef && 
                    fromNode.containerRef.name === toNode.containerRef.name) {
                    continue;
                }

                // Check line of sight
                const losResult = this.hasLineOfSight(fromNode.position, toNode.position);
                const distance = this.calcDistance3d(fromNode.position, toNode.position);

                // Create bidirectional edges
                const forwardEdge: VisibilityEdge = {
                    fromNode,
                    toNode,
                    distance,
                    hasLOS: losResult.hasLos,
                    obstruction: losResult.obstruction
                };

                const backwardEdge: VisibilityEdge = {
                    fromNode: toNode,
                    toNode: fromNode,
                    distance,
                    hasLOS: losResult.hasLos,
                    obstruction: losResult.obstruction
                };

                // Add edges to the graph
                this.visibilityGraph.get(fromKey)?.push(forwardEdge);
                this.visibilityGraph.get(toKey)?.push(backwardEdge);
            }
        }
    }

    /**
     * Generate a unique key for a navigation node
     */
    private getNodeKey(node: NavNode): string {
        return `${node.position.x},${node.position.y},${node.position.z}`;
    }

    /**
     * Enhanced line of sight check with improved ray casting and obstruction detection
     */
    private hasLineOfSight(from: Vector3, to: Vector3): { hasLos: boolean, obstruction: ObjectContainer | null } {
        const direction: Vector3 = {
            x: to.x - from.x,
            y: to.y - from.y,
            z: to.z - from.z
        };
        
        const distance = this.calcDistance3d(from, to);
        
        // Check each celestial body for potential obstruction
        for (const container of this.containers) {
            // Skip non-physical containers or very small objects
            if (container.bodyRadius <= 0 || 
                container.cont_type === ContainerType.Lagrange || 
                container.cont_type === ContainerType.JumpPoint) {
                continue;
            }
            
            const containerPos: Vector3 = {
                x: container.posX,
                y: container.posY,
                z: container.posZ
            };
            
            // Calculate the closest point on the line to the container center using vector projection
            const t = (
                (containerPos.x - from.x) * direction.x +
                (containerPos.y - from.y) * direction.y +
                (containerPos.z - from.z) * direction.z
            ) / (distance * distance);
            
            // Clamp t to [0, 1] to keep it on the line segment
            const clampedT = Math.max(0, Math.min(1, t));
            
            // Calculate the closest point on the line
            const closestPoint: Vector3 = {
                x: from.x + clampedT * direction.x,
                y: from.y + clampedT * direction.y,
                z: from.z + clampedT * direction.z
            };
            
            // Calculate distance from closest point to container center
            const distToContainer = this.calcDistance3d(closestPoint, containerPos);
            
            // If this distance is less than the body radius, the line is obstructed
            // Using a slightly larger safety margin (1.05x) to account for atmosphere
            if (distToContainer < container.bodyRadius * 1.05) {
                return { hasLos: false, obstruction: container };
            }
        }
        
        return { hasLos: true, obstruction: null };
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
     * Unified coordinate transformation method that handles both global-to-local and local-to-global
     * transformations, with caching for performance optimization
     */
    private transformCoordinates(
        coords: Vector3,
        container: ObjectContainer,
        direction: 'toGlobal' | 'toLocal'
    ): Vector3 {
        // Generate cache key
        const cacheKey = `${coords.x},${coords.y},${coords.z},${container.name},${direction}`;
        
        // Check if we have this transformation cached
        const cachedResult = this.coordTransformCache.get(cacheKey);
        if (cachedResult) {
            return cachedResult;
        }
        
        // Get elapsed time and calculate rotation angle
        const elapsedUTCTimeSinceSimulationStart = this.getElapsedUTCServerTime(); // In days
        const lengthOfDayDecimal = container.rotVelX * 3600 / 86400; // Convert hours to day fraction
        const totalCycles = elapsedUTCTimeSinceSimulationStart / lengthOfDayDecimal;
        const currentCycleDez = totalCycles % 1;
        const currentCycleDeg = currentCycleDez * 360;
        const currentCycleAngle = container.rotAdjX + currentCycleDeg;
        const angleRad = currentCycleAngle * Math.PI / 180;
        
        let result: Vector3;
        
        if (direction === 'toLocal') {
            // Global to local transformation
            const dx = container.posX - coords.x;
            const dy = container.posY - coords.y;
            const dz = container.posZ - coords.z;

            // Apply inverse rotation matrix
            const rotX = dx * Math.cos(-angleRad) - dy * Math.sin(-angleRad);
            const rotY = dx * Math.sin(-angleRad) + dy * Math.cos(-angleRad);

            result = {
                x: rotX / 1000, // Convert to km for display
                y: rotY / 1000,
                z: dz / 1000
            };
        } else {
            // Local to global transformation
            // Apply rotation matrix
            const rotX = coords.x * Math.cos(angleRad) - coords.y * Math.sin(angleRad);
            const rotY = coords.x * Math.sin(angleRad) + coords.y * Math.cos(angleRad);

            // Transform to global coordinate system
            result = {
                x: container.posX + rotX * 1000, // Convert back to meters
                y: container.posY + rotY * 1000,
                z: container.posZ + coords.z * 1000
            };
        }
        
        // Cache the result
        this.coordTransformCache.set(cacheKey, result);
        
        return result;
    }

    /**
     * Bidirectional A* pathfinding algorithm optimized for 3D space navigation
     * This approach searches from both start and end simultaneously, which is
     * significantly more efficient for large 3D spaces with sparse connectivity
     */
    private findPathBidirectional(startPos: Vector3, endPos: Vector3): NavNode[] | null {
        // Create start and end nodes
        const startNode = new NavNode(startPos, 'origin', 'Start Position');
        startNode.searchDirection = 'forward';
        
        const endNode = new NavNode(endPos, 'destination', 'Destination');
        endNode.searchDirection = 'backward';
        
        // Check if there's a direct path
        const { hasLos, obstruction } = this.hasLineOfSight(startPos, endPos);
        if (hasLos) {
            // Direct path available
            const directPath = [startNode, endNode];
            endNode.parentNode = startNode;
            return directPath;
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
        const visibleFromStart = this.findVisibleMarkers(startPos);
        const visibleFromEnd = this.findVisibleMarkers(endPos);
        
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
        while (forwardOpenSet.length > 0 && backwardOpenSet.length > 0) {
            iterations++;
            if (iterations > this.MAX_ITERATIONS) {
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
            return this.reconstructBidirectionalPath(
                bestMeetingPoint.value.forwardNode, 
                bestMeetingPoint.value.backwardNode
            );
        }
        
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
                    bestMeetingPoint = {
                        value: {
                            forwardNode: direction === 'forward' ? currentNode : oppositeNode,
                            backwardNode: direction === 'backward' ? currentNode : oppositeNode,
                            totalCost
                        }
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
                    neighbor.hCost = this.calcDistance3d(neighbor.position, bestMeetingPoint?.value?.backwardNode.position || { x: 0, y: 0, z: 0 });
                } else {
                    neighbor.hCost = this.calcDistance3d(neighbor.position, bestMeetingPoint?.value?.forwardNode.position || { x: 0, y: 0, z: 0 });
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
        return [...forwardPath, ...backwardPath.slice(1)];
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
            
            const distance = this.calcDistance3d(from.position, to.position);
            
            // Determine travel type based on distance and node types
            // Quantum travel is used for distances > 20km and when not traveling to/from an OM
            const travelType: 'quantum' | 'sublight' = 
                (distance > 20000 && from.type !== 'om' && to.type !== 'om') 
                    ? 'quantum' 
                    : 'sublight';
            
            // Calculate estimated time
            const estimatedTime = this.calculateTravelTime(distance, travelType);
            
            // Calculate direction
            const direction = this.calculateEulerAngles(from.position, to.position);
            
            // Check for obstructions in this segment
            const { hasLos, obstruction } = this.hasLineOfSight(from.position, to.position);
            
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
            pathComplexity
        };
    }

    /**
     * Plan a navigation route using the optimized bidirectional A* algorithm
     */
    public planNavigation(destinationName: string): NavigationPlan | null {
        if (!this.currentPosition) {
            console.error("Current position not set");
            return null;
        }
        
        // Find destination in POIs or containers
        let destinationPos: Vector3 | null = null;
        
        // Check POIs
        const poiDestination = this.pois.find(poi => poi.name === destinationName);
        if (poiDestination) {
            destinationPos = getCoordinates(poiDestination);
        }
        
        // Check containers
        if (!destinationPos) {
            const containerDestination = this.containers.find(container => container.name === destinationName);
            if (containerDestination) {
                destinationPos = {
                    x: containerDestination.posX,
                    y: containerDestination.posY,
                    z: containerDestination.posZ
                };
            }
        }

        if (!destinationPos) {
            console.error(`Destination '${destinationName}' not found`);
            return null;
        }
        
        // Log key information for debugging
        console.log(`Planning route to ${destinationName}`);
        console.log(`Destination coordinates: ${JSON.stringify(destinationPos)}`);
        console.log(`Current position: ${JSON.stringify(this.currentPosition)}`);
        
        // Find path using bidirectional A*
        const path = this.findPathBidirectional(this.currentPosition, destinationPos);
        
        if (!path) {
            console.error("No viable path found");
            
            // Fallback: attempt to find path to closest visible marker near destination
            const visibleFromStart = this.findVisibleMarkers(this.currentPosition);
            
            if (visibleFromStart.length > 0) {
                console.log("Attempting fallback routing through visible markers...");
                
                // Find marker closest to destination
                let closestMarker: NavNode | null = null;
                let minDistance = Number.MAX_VALUE;
                
                for (const { node } of visibleFromStart) {
                    const distToDest = this.calcDistance3d(node.position, destinationPos);
                    if (distToDest < minDistance) {
                        minDistance = distToDest;
                        closestMarker = node;
                    }
                }
                
                if (closestMarker) {
                    console.log(`Fallback to closest marker: ${closestMarker.name}`);
                    
                    // Create a minimal path through the closest marker
                    const fallbackPath = [
                        new NavNode(this.currentPosition, 'origin', 'Start Position'),
                        closestMarker,
                        new NavNode(destinationPos, 'destination', 'Destination')
                    ];
                    
                    return this.createNavigationPlan(fallbackPath);
                }
            }
            
            return null;
        }
        
        // Create navigation plan
        return this.createNavigationPlan(path);
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
        
        if (plan.obstructionDetected) {
            instructions += "⚠️ OBSTRUCTIONS DETECTED:\n";
            instructions += `Celestial bodies blocking direct path: ${plan.obstructions.join(', ')}\n`;
            instructions += `Multiple jumps required (${plan.segments.length} segments, ${plan.quantumJumps} quantum jumps)\n\n`;
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
}