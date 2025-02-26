import { getCoordinates, NavigationResult, ObjectContainer, PointOfInterest, Vector3 } from "./types";

export class SCNavigationCore {
    pois: PointOfInterest[] = [];
    containers: ObjectContainer[] = [];
    currentPosition: Vector3 | null = null;
    previousPosition: Vector3 | null = null;
    positionTimestamp: number = 0;
    previousTimestamp: number = 0;
    selectedPOI: PointOfInterest | null = null;
    currentObjectContainer: ObjectContainer | null = null;

    /**
     * Calculate 3D Euclidean distance between two points
     */
    protected calcDistance3d(p1: Vector3, p2: Vector3): number {
        return Math.sqrt(
            Math.pow(p1.x - p2.x, 2) +
            Math.pow(p1.y - p2.y, 2) +
            Math.pow(p1.z - p2.z, 2)
        );
    }

    /**
     * Initialize with data sources
     */
    constructor(
        poiData: PointOfInterest[],
        containerData: ObjectContainer[]
    ) {
        this.pois = poiData;
        this.containers = containerData;
    }

    /**
     * Update current player position
     */
    public updatePosition(x: number, y: number, z: number): void {
        // Store previous position for velocity calculation
        if (this.currentPosition) {
            this.previousPosition = { ...this.currentPosition };
            this.previousTimestamp = this.positionTimestamp;
        }

        this.currentPosition = { x, y, z };
        this.positionTimestamp = Date.now();

        // Detect current object container (planet/moon)
        this.detectCurrentObjectContainer();
    }

    /**
     * Determine which celestial body the player is near/on
     */
    private detectCurrentObjectContainer(): void {
        if (!this.currentPosition) return;

        this.currentObjectContainer = null;

        for (const container of this.containers) {
            const distance = this.calcDistance3d(
                this.currentPosition,
                { x: container.posX, y: container.posY, z: container.posZ }
            );

            // If within the orbital marker radius * 1.5, consider player to be within this container
            if (distance <= container.omRadius * 1.5) {
                this.currentObjectContainer = container;
                break;
            }
        }
    }

    /**
     * Select a point of interest by ID
     */
    public selectPOI(poiId: number): PointOfInterest | null {
        const poi = this.pois.find(p => p.id === poiId);
        this.selectedPOI = poi || null;
        return this.selectedPOI;
    }

    /**
     * Calculate velocity vector based on position changes
     */
    private calculateVelocity(): Vector3 | null {
        if (!this.currentPosition || !this.previousPosition ||
            this.positionTimestamp === this.previousTimestamp) {
            return null;
        }

        const timeDelta = (this.positionTimestamp - this.previousTimestamp) / 1000; // in seconds

        return {
            x: (this.currentPosition.x - this.previousPosition.x) / timeDelta,
            y: (this.currentPosition.y - this.previousPosition.y) / timeDelta,
            z: (this.currentPosition.z - this.previousPosition.z) / timeDelta
        };
    }

    /**
     * Get elapsed time since simulation start in days
     */
    protected getElapsedUTCServerTime(): number {
        // Simulation start date is January 1, 2020
        const simulationStartTime = new Date(2020, 0, 1, 0, 0, 0, 0).getTime();
        const currentTime = Date.now();

        // Convert milliseconds to days
        return (currentTime - simulationStartTime) / (1000 * 60 * 60 * 24);
    }

    /**
     * Calculate Euler angles for direction from current position to destination
     */
    protected calculateEulerAngles(
        current: Vector3,
        destination: Vector3
    ): { pitch: number, roll: number, yaw: number } {
        // Calculate deltas between current and destination positions
        const dx = destination.x - current.x;
        const dy = destination.y - current.y;
        const dz = destination.z - current.z;

        // Calculate distance in the XY plane
        const distanceXY = Math.sqrt(dx * dx + dy * dy);

        // Calculate pitch (vertical angle)
        const pitch = Math.atan2(dz, distanceXY) * (180 / Math.PI);

        // Roll is 0 for simplicity
        const roll = 0;

        // Calculate yaw (horizontal angle)
        let yaw = Math.atan2(dy, dx) * (180 / Math.PI);

        // Convert to game's coordinate system
        if (yaw > 90) {
            yaw = yaw - 270;
        } else {
            yaw = yaw + 90;
        }

        return { pitch, roll, yaw };
    }

    /**
     * Calculate angular deviation between current trajectory and destination
     */
    private calculateAngularDeviation(
        prevPos: Vector3,
        currentPos: Vector3,
        destPos: Vector3
    ): number {
        // Vector from previous to current position = current trajectory
        const vx = currentPos.x - prevPos.x;
        const vy = currentPos.y - prevPos.y;
        const vz = currentPos.z - prevPos.z;

        // Vector from current to destination
        const dx = destPos.x - currentPos.x;
        const dy = destPos.y - currentPos.y;
        const dz = destPos.z - currentPos.z;

        // Calculate dot product
        const dotProduct = vx * dx + vy * dy + vz * dz;

        // Calculate magnitudes
        const vMag = Math.sqrt(vx * vx + vy * vy + vz * vz);
        const dMag = Math.sqrt(dx * dx + dy * dy + dz * dz);

        // Calculate angle in radians and convert to degrees
        const angle = Math.acos(dotProduct / (vMag * dMag)) * (180 / Math.PI);

        return angle;
    }

    /**
     * Find closest orbital marker to a position on a planet
     */
    private findClosestOrbitalMarker(
        _position: Vector3,
        container: ObjectContainer
    ): { name: string; distance: number } {
        // Keep stub implementation as base class doesn't have orbital marker data
        console.warn(`Base implementation called for ${container.name}`);
        return {
            name: "OM-3", // Placeholder
            distance: 100000
        };
    }

    /**
     * Find closest QT beacon to a position
     */
    private findClosestQTBeacon(position: Vector3): { name: string; distance: number } | null {
        if (this.pois.length === 0) return null;

        let closestBeacon = null;
        let minDistance = Number.MAX_VALUE;

        for (const poi of this.pois) {
            if (poi.hasQTMarker) {
                const distance = this.calcDistance3d(position, getCoordinates(poi));
                if (distance < minDistance) {
                    minDistance = distance;
                    closestBeacon = poi;
                }
            }
        }

        if (closestBeacon) {
            return {
                name: closestBeacon.name,
                distance: minDistance
            };
        }

        return null;
    }

    /**
     * Calculate ETA based on current velocity and distance
     */
    private calculateETA(
        distance: number,
        velocity: Vector3
    ): number {
        // Calculate speed (magnitude of velocity vector)
        const speed = Math.sqrt(
            velocity.x * velocity.x +
            velocity.y * velocity.y +
            velocity.z * velocity.z
        );

        // If not moving or moving away, return -1
        if (speed <= 0) return -1;

        // Return ETA in seconds
        return distance / speed;
    }

    /**
     * Get comprehensive navigation data to selected POI
     */
    public getNavigationData(): NavigationResult | null {
        if (!this.currentPosition || !this.selectedPOI) {
            return null;
        }
    
        let destinationCoords = getCoordinates(this.selectedPOI);
    
        // If POI is on a planet, adjust for planetary rotation
        if (this.selectedPOI.objContainer) {
            const poiContainer = this.containers.find(
                c => c.name === this.selectedPOI?.objContainer
            );
    
            if (poiContainer) {
                // The actual coordinates would need to be calculated with 
                // the planet's current rotation
                // This is a simplification
                destinationCoords = this.calculateRotatedPlanetaryCoordinates(
                    getCoordinates(this.selectedPOI),
                    poiContainer
                );
            }
        }
    
        // Calculate distance
        const distance = this.calcDistance3d(this.currentPosition, destinationCoords);
    
        // Calculate direction
        const direction = this.calculateEulerAngles(this.currentPosition, destinationCoords);
    
        // Calculate angular deviation if we have a previous position
        let angularDeviation = undefined;
        if (this.previousPosition) {
            angularDeviation = this.calculateAngularDeviation(
                this.previousPosition,
                this.currentPosition,
                destinationCoords
            );
        }
    
        // Calculate velocity and ETA
        const velocity = this.calculateVelocity();
        let eta = -1;
        if (velocity) {
            eta = this.calculateETA(distance, velocity);
        }
    
        // Get closest orbital marker if on a planet
        let closestOrbitalMarker = undefined;
        if (this.currentObjectContainer) {
            closestOrbitalMarker = this.findClosestOrbitalMarker(
                this.currentPosition,
                this.currentObjectContainer
            );
        }
    
        // Get closest QT beacon
        const closestQTBeacon = this.findClosestQTBeacon(this.currentPosition);
    
        // Safely create a NavigationResult with explicit undefined handling
        return {
            distance,
            direction,
            eta,
            // Explicit type coercion for undefined values with null coalescing
            angularDeviation: angularDeviation !== undefined ? angularDeviation : undefined,
            closestOrbitalMarker: closestOrbitalMarker !== undefined ? closestOrbitalMarker : undefined,
            closestQTBeacon: closestQTBeacon !== null ? closestQTBeacon : undefined
        };
    }

    /**
     * Calculate coordinates accounting for planetary rotation
     */
    private calculateRotatedPlanetaryCoordinates(
        localCoords: Vector3,
        container: ObjectContainer
    ): Vector3 {
        // Get elapsed time and calculate rotation angle based on rotVelX
        const elapsedUTCTimeSinceSimulationStart = this.getElapsedUTCServerTime();
        const lengthOfDayDecimal = container.rotVelX * 3600 / 86400;
        const totalCycles = elapsedUTCTimeSinceSimulationStart / lengthOfDayDecimal;
        const currentCycleDez = totalCycles % 1;
        const currentCycleDeg = currentCycleDez * 360;
        const currentCycleAngle = container.rotAdjX + currentCycleDeg;

        // Calculate rotation with precise angular transform
        const angleRad = currentCycleAngle * Math.PI / 180;

        // Apply rotation matrix to the local coordinates
        const rotX = localCoords.x * Math.cos(angleRad) -
            localCoords.y * Math.sin(angleRad);
        const rotY = localCoords.x * Math.sin(angleRad) +
            localCoords.y * Math.cos(angleRad);

        // Transform back to global coordinate system by adding planet position
        return {
            x: container.posX + rotX * 1000, // Convert back to meters
            y: container.posY + rotY * 1000,
            z: container.posZ + localCoords.z * 1000
        };
    }

    /**
     * Convert system coordinates to non-rotated static coordinates
     * This function reverses the planetary rotation to get static coordinates
     * @param globalPos The global position in the system
     * @param container The container (planet/moon) to calculate against
     * @returns Vector3 coordinates in the static non-rotated reference frame
     */
    public convertToStaticCoordinates(
        globalPos: Vector3,
        container: ObjectContainer
    ): Vector3 {
        // Check if container is valid to prevent NaN results
        if (!container || container.rotVelX === 0) {
            console.warn("Invalid container or zero rotation velocity");
            return { ...globalPos }; // Return copy of input to avoid NaN
        }

        // Calculate difference vectors (ECEF coordinate system)
        const dx = globalPos.x - container.posX;
        const dy = globalPos.y - container.posY;
        const dz = globalPos.z - container.posZ;

        // Get elapsed time and calculate rotation angle
        const elapsedUTCTimeSinceSimulationStart = this.getElapsedUTCServerTime();
        const lengthOfDayDecimal = container.rotVelX * 3600 / 86400; // Convert hours to day fraction
        
        // Prevent division by zero
        if (lengthOfDayDecimal === 0) {
            console.warn("Length of day decimal is zero, cannot calculate rotation");
            return { ...globalPos };
        }
        
        const totalCycles = elapsedUTCTimeSinceSimulationStart / lengthOfDayDecimal;
        const currentCycleDez = totalCycles % 1;
        const currentCycleDeg = currentCycleDez * 360;
        const currentCycleAngle = container.rotAdjX + currentCycleDeg;

        // Convert angle to radians
        const angleRad = currentCycleAngle * Math.PI / 180;

        // Apply inverse rotation matrix to transform from rotated to static coordinates
        // We use the negative angle to reverse the rotation
        const staticX = dx * Math.cos(-angleRad) - dy * Math.sin(-angleRad);
        const staticY = dx * Math.sin(-angleRad) + dy * Math.cos(-angleRad);

        // Return the static coordinates relative to the container's position
        const result = {
            x: container.posX + staticX,
            y: container.posY + staticY,
            z: container.posZ + dz
        };
        
        // Debug output to help diagnose NaN issues
        if (isNaN(result.x) || isNaN(result.y) || isNaN(result.z)) {
            console.error("NaN detected in convertToStaticCoordinates:", {
                input: globalPos,
                container: {
                    posX: container.posX,
                    posY: container.posY,
                    posZ: container.posZ,
                    rotVelX: container.rotVelX,
                    rotAdjX: container.rotAdjX
                },
                angleRad,
                dx, dy, dz,
                staticX, staticY
            });
        }
        
        return result;
    }
}