import { ObjectContainer, Vector3 } from "./types";

/**
 * Specialized utility for coordinate transformations in space navigation systems.
 * Implements high-performance quaternion-based transformations with caching.
 */
export class CoordinateTransformer {
    // Cache for expensive coordinate transformations
    private static transformCache: Map<string, Vector3> = new Map();
    // Cache size limit to prevent memory leaks
    private static readonly CACHE_LIMIT = 2048;
    
    /**
     * Generate a normalized quaternion from Euler angles (in degrees)
     * @param pitch Pitch in degrees (X-axis rotation)
     * @param yaw Yaw in degrees (Y-axis rotation)
     * @param roll Roll in degrees (Z-axis rotation)
     * @returns Normalized quaternion as [w, x, y, z]
     */
    public static eulerToQuaternion(pitch: number, yaw: number, roll: number): [number, number, number, number] {
        // Convert to radians
        const pitchRad = pitch * Math.PI / 180;
        const yawRad = yaw * Math.PI / 180;
        const rollRad = roll * Math.PI / 180;
        
        // Calculate half angles
        const cx = Math.cos(pitchRad / 2);
        const sx = Math.sin(pitchRad / 2);
        const cy = Math.cos(yawRad / 2);
        const sy = Math.sin(yawRad / 2);
        const cz = Math.cos(rollRad / 2);
        const sz = Math.sin(rollRad / 2);
        
        // Calculate quaternion components using the ZYX convention
        const w = cx * cy * cz + sx * sy * sz;
        const x = sx * cy * cz - cx * sy * sz;
        const y = cx * sy * cz + sx * cy * sz;
        const z = cx * cy * sz - sx * sy * cz;
        
        // Normalize the quaternion
        const magnitude = Math.sqrt(w*w + x*x + y*y + z*z);
        return [
            w / magnitude,
            x / magnitude,
            y / magnitude,
            z / magnitude
        ];
    }
    
    /**
     * Convert quaternion to Euler angles (in degrees)
     * @param quat Quaternion as [w, x, y, z]
     * @returns Euler angles as { pitch, yaw, roll } in degrees
     */
    public static quaternionToEuler(quat: [number, number, number, number]): { pitch: number, yaw: number, roll: number } {
        const [w, x, y, z] = quat;
        
        // Calculate Euler angles from quaternion (ZYX convention)
        // Roll (z-axis rotation)
        const sinr_cosp = 2 * (w * x + y * z);
        const cosr_cosp = 1 - 2 * (x * x + y * y);
        const roll = Math.atan2(sinr_cosp, cosr_cosp);
        
        // Pitch (x-axis rotation)
        const sinp = 2 * (w * y - z * x);
        let pitch;
        if (Math.abs(sinp) >= 1) {
            // Use 90 degrees if out of range (gimbal lock)
            pitch = Math.sign(sinp) * Math.PI / 2;
        } else {
            pitch = Math.asin(sinp);
        }
        
        // Yaw (y-axis rotation)
        const siny_cosp = 2 * (w * z + x * y);
        const cosy_cosp = 1 - 2 * (y * y + z * z);
        const yaw = Math.atan2(siny_cosp, cosy_cosp);
        
        // Convert to degrees
        return {
            pitch: pitch * 180 / Math.PI,
            yaw: yaw * 180 / Math.PI,
            roll: roll * 180 / Math.PI
        };
    }
    
    /**
     * Apply a quaternion rotation to a vector
     * @param v Vector to rotate
     * @param q Quaternion as [w, x, y, z]
     * @returns Rotated vector
     */
    public static rotateVectorByQuaternion(v: Vector3, q: [number, number, number, number]): Vector3 {
        const [w, qx, qy, qz] = q;
        
        // Convert vector to quaternion form (0, vx, vy, vz)
        const vq: [number, number, number, number] = [0, v.x, v.y, v.z];
        
        // Calculate the quaternion conjugate
        const qConjugate: [number, number, number, number] = [w, -qx, -qy, -qz];
        
        // Perform rotation: q * v * q^-1
        const temp = this.multiplyQuaternions(q, vq);
        const result = this.multiplyQuaternions(temp, qConjugate);
        
        // Extract the vector part
        return {
            x: result[1],
            y: result[2],
            z: result[3]
        };
    }
    
    /**
     * Multiply two quaternions
     * @param q1 First quaternion as [w, x, y, z]
     * @param q2 Second quaternion as [w, x, y, z]
     * @returns Result quaternion as [w, x, y, z]
     */
    private static multiplyQuaternions(
        q1: [number, number, number, number], 
        q2: [number, number, number, number]
    ): [number, number, number, number] {
        const [w1, x1, y1, z1] = q1;
        const [w2, x2, y2, z2] = q2;
        
        return [
            w1 * w2 - x1 * x2 - y1 * y2 - z1 * z2,
            w1 * x2 + x1 * w2 + y1 * z2 - z1 * y2,
            w1 * y2 - x1 * z2 + y1 * w2 + z1 * x2,
            w1 * z2 + x1 * y2 - y1 * x2 + z1 * w2
        ];
    }
    
    /**
     * Get elapsed time since simulation start in days
     * Uses January 1, 2020 as the simulation start date
     */
    private static getElapsedUTCServerTime(): number {
        // Simulation start date is January 1, 2020
        const simulationStartTime = new Date(2020, 0, 1, 0, 0, 0, 0).getTime();
        const currentTime = Date.now();

        // Convert milliseconds to days
        return (currentTime - simulationStartTime) / (1000 * 60 * 60 * 24);
    }

    /**
     * Unified coordinate transformation method with quaternion-based rotation
     * Handles both global-to-local and local-to-global transformations
     * @param coords Vector3 coordinates to transform
     * @param container The celestial body reference frame
     * @param direction Direction of transformation
     * @returns Transformed coordinates
     */
    public static transformCoordinates(
        coords: Vector3,
        container: ObjectContainer,
        direction: 'toGlobal' | 'toLocal'
    ): Vector3 {
        // Generate cache key
        const cacheKey = `${coords.x.toFixed(2)},${coords.y.toFixed(2)},${coords.z.toFixed(2)},${container.name},${direction}`;
        
        // Check cache first
        const cachedResult = this.transformCache.get(cacheKey);
        if (cachedResult) {
            return cachedResult;
        }
        
        // Get elapsed time and calculate current rotation
        const elapsedDays = this.getElapsedUTCServerTime();
        const dayLengthFraction = container.rotVelX * 3600 / 86400; // Convert hours to day fraction
        const totalRotations = elapsedDays / dayLengthFraction;
        const currentRotationFraction = totalRotations % 1;
        const currentRotationDegrees = currentRotationFraction * 360;
        const absoluteRotationDegrees = container.rotAdjX + currentRotationDegrees;
        
        // Create rotation quaternion for the celestial body
        // We only need rotation around Z-axis for planetary rotation
        const rotationQuat = this.eulerToQuaternion(0, 0, absoluteRotationDegrees);
        const inverseRotationQuat: [number, number, number, number] = [
            rotationQuat[0], 
            -rotationQuat[1], 
            -rotationQuat[2], 
            -rotationQuat[3]
        ];
        
        let result: Vector3;
        
        if (direction === 'toLocal') {
            // Global to local transformation
            
            // Step 1: Translate to origin-centered coordinates
            const centered: Vector3 = {
                x: coords.x - container.posX,
                y: coords.y - container.posY,
                z: coords.z - container.posZ
            };
            
            // Step 2: Apply inverse rotation to get local coordinates
            const rotated = this.rotateVectorByQuaternion(centered, inverseRotationQuat);
            
            // Step 3: Scale to appropriate units (for display)
            result = {
                x: rotated.x / 1000, // Convert to km for display
                y: rotated.y / 1000,
                z: rotated.z / 1000
            };
        } else {
            // Local to global transformation
            
            // Step 1: Scale to appropriate units (from display)
            const scaled: Vector3 = {
                x: coords.x * 1000, // Convert from km to meters
                y: coords.y * 1000,
                z: coords.z * 1000
            };
            
            // Step 2: Apply rotation to get global orientation
            const rotated = this.rotateVectorByQuaternion(scaled, rotationQuat);
            
            // Step 3: Translate to global coordinates
            result = {
                x: rotated.x + container.posX,
                y: rotated.y + container.posY,
                z: rotated.z + container.posZ
            };
        }
        
        // Cache the result
        this.transformCache.set(cacheKey, result);
        
        // Manage cache size to prevent memory leaks
        if (this.transformCache.size > this.CACHE_LIMIT) {
            // Remove oldest entries (first 20% of the cache)
            const keysToRemove = Array.from(this.transformCache.keys())
                .slice(0, Math.floor(this.CACHE_LIMIT * 0.2));
            
            keysToRemove.forEach(key => this.transformCache.delete(key));
        }
        
        return result;
    }
    
    /**
     * Calculate relative velocity between two objects accounting for celestial body rotation
     * @param pos1 Position at time t1
     * @param pos2 Position at time t2
     * @param t1 Time in milliseconds for pos1
     * @param t2 Time in milliseconds for pos2
     * @param container Optional celestial body reference frame
     * @returns Velocity vector in m/s
     */
    public static calculateVelocity(
        pos1: Vector3, 
        pos2: Vector3, 
        t1: number, 
        t2: number,
        container?: ObjectContainer
    ): Vector3 {
        if (t2 <= t1) {
            return { x: 0, y: 0, z: 0 };
        }
        
        const timeDelta = (t2 - t1) / 1000; // Convert to seconds
        
        // If no container, calculate simple velocity
        if (!container) {
            return {
                x: (pos2.x - pos1.x) / timeDelta,
                y: (pos2.y - pos1.y) / timeDelta,
                z: (pos2.z - pos1.z) / timeDelta
            };
        }
        
        // For positions on a celestial body, we need to account for rotation
        
        // Convert both positions to the local reference frame
        const localPos1 = this.transformCoordinates(pos1, container, 'toLocal');
        const localPos2 = this.transformCoordinates(pos2, container, 'toLocal');
        
        // Calculate velocity in the local reference frame
        const localVelocity = {
            x: (localPos2.x - localPos1.x) * 1000 / timeDelta, // Convert km to m for m/s
            y: (localPos2.y - localPos1.y) * 1000 / timeDelta,
            z: (localPos2.z - localPos1.z) * 1000 / timeDelta
        };
        
        // Add rotational velocity component
        // Angular velocity in radians per second
        const angularVelocity = (container.rotVelX * 2 * Math.PI) / (3600); // rotVelX is in hours for a full rotation
        
        // Calculate tangential velocity component at this radius
        const radiusVector = {
            x: localPos2.x * 1000, // Convert to meters
            y: localPos2.y * 1000,
            z: 0 // Assuming rotation around z-axis
        };
        
        const radius = Math.sqrt(radiusVector.x * radiusVector.x + radiusVector.y * radiusVector.y);
        
        // Tangential velocity is perpendicular to radius vector
        const tangentialVelocity = {
            x: -radiusVector.y * angularVelocity / radius,
            y: radiusVector.x * angularVelocity / radius,
            z: 0
        };
        
        // Total velocity is local velocity plus tangential velocity
        return {
            x: localVelocity.x + tangentialVelocity.x,
            y: localVelocity.y + tangentialVelocity.y,
            z: localVelocity.z + tangentialVelocity.z
        };
    }
    
    /**
     * Calculates planetary coordinates (lat/long) from global position
     * @param globalPos Global position vector
     * @param container Celestial body reference frame
     * @returns {lat, long, altitude} in degrees and meters
     */
    public static calculatePlanetaryCoordinates(
        globalPos: Vector3, 
        container: ObjectContainer
    ): { lat: number, long: number, altitude: number } {
        // Convert to local reference frame
        const localPos = this.transformCoordinates(globalPos, container, 'toLocal');
        
        // Calculate radius from center (in km)
        const radius = Math.sqrt(
            localPos.x * localPos.x + 
            localPos.y * localPos.y + 
            localPos.z * localPos.z
        );
        
        // Calculate altitude (in meters) above surface
        const altitude = (radius * 1000) - container.bodyRadius;
        
        // Calculate latitude and longitude
        // Longitude: atan2(y, x)
        const longitude = Math.atan2(localPos.y, localPos.x) * 180 / Math.PI;
        
        // Latitude: asin(z / radius)
        const latitude = Math.asin(localPos.z / radius) * 180 / Math.PI;
        
        return {
            lat: latitude,
            long: longitude,
            altitude: altitude
        };
    }
    
    /**
     * Calculates global position from planetary coordinates
     * @param lat Latitude in degrees
     * @param long Longitude in degrees
     * @param altitude Altitude in meters above surface
     * @param container Celestial body reference frame
     * @returns Global position vector
     */
    public static globalPositionFromPlanetaryCoords(
        lat: number, 
        long: number, 
        altitude: number, 
        container: ObjectContainer
    ): Vector3 {
        // Convert lat/long to radians
        const latRad = lat * Math.PI / 180;
        const longRad = long * Math.PI / 180;
        
        // Calculate radius from center (in km)
        const radius = container.bodyRadius + altitude;
        const radiusKm = radius / 1000;
        
        // Calculate local position
        const localPos: Vector3 = {
            x: radiusKm * Math.cos(latRad) * Math.cos(longRad),
            y: radiusKm * Math.cos(latRad) * Math.sin(longRad),
            z: radiusKm * Math.sin(latRad)
        };
        
        // Transform to global coordinates
        return this.transformCoordinates(localPos, container, 'toGlobal');
    }
}
