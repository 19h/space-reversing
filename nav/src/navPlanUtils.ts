import { ObjectContainer, Vector3 } from "./types";

/**
 * Specialized utility for coordinate transformations in space navigation systems.
 * Implements high-precision quaternion-based transformations with optimized caching.
 */
export class CoordinateTransformer {
    // Cache for expensive coordinate transformations with pre-allocated size
    private static transformCache: Map<string, Vector3> = new Map();
    
    // Cache size controls
    private static readonly CACHE_LIMIT = 2048;
    private static readonly CACHE_PRUNE_THRESHOLD = 0.2; // Prune 20% of cache when limit reached
    
    // Cache access statistics for LRU implementation
    private static cacheHits = 0;
    private static cacheMisses = 0;
    private static cacheTimestamps: Map<string, number> = new Map();
    
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
     * Generate a cache key with precision control to avoid float comparison issues
     */
    private static generateCacheKey(
        coords: Vector3,
        container: ObjectContainer,
        direction: 'toGlobal' | 'toLocal'
    ): string {
        // Use fixed precision to prevent floating point comparison issues
        // but maintain enough precision for small-scale differences
        return `${coords.x.toFixed(6)},${coords.y.toFixed(6)},${coords.z.toFixed(6)},${container.name},${direction}`;
    }
    
    /**
     * Prune least recently used cache entries when cache size limit is reached
     */
    private static pruneCache(): void {
        if (this.transformCache.size <= this.CACHE_LIMIT) {
            return;
        }
        
        // Get all cache keys with their timestamps
        const entries = Array.from(this.cacheTimestamps.entries())
            .sort((a, b) => a[1] - b[1]); // Sort by timestamp (oldest first)
        
        // Calculate how many entries to remove
        const removeCount = Math.ceil(this.CACHE_LIMIT * this.CACHE_PRUNE_THRESHOLD);
        
        // Remove oldest entries
        const keysToRemove = entries.slice(0, removeCount).map(entry => entry[0]);
        
        keysToRemove.forEach(key => {
            this.transformCache.delete(key);
            this.cacheTimestamps.delete(key);
        });
        
        console.log(`Pruned ${removeCount} entries from coordinate transform cache`);
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
        // Generate cache key with precision control
        const cacheKey = this.generateCacheKey(coords, container, direction);
        
        // Check cache first
        const cachedResult = this.transformCache.get(cacheKey);
        if (cachedResult) {
            // Update timestamp for LRU caching
            this.cacheTimestamps.set(cacheKey, Date.now());
            this.cacheHits++;
            return { ...cachedResult }; // Return a copy to prevent mutation
        }
        
        this.cacheMisses++;
        
        // Get elapsed time and calculate current rotation
        const elapsedDays = this.getElapsedUTCServerTime();
        
        // Safety check for invalid rotation velocity
        if (container.rotVelX === 0) {
            console.warn(`Container ${container.name} has zero rotation velocity. Using dummy value.`);
            container.rotVelX = 24; // Assume 24-hour day as fallback
        }
        
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
        
        // Verify result for NaN values
        if (isNaN(result.x) || isNaN(result.y) || isNaN(result.z)) {
            console.error("NaN detected in coordinate transformation:", {
                input: coords,
                container: container.name,
                direction,
                rotation: absoluteRotationDegrees
            });
            
            // Fallback to direct scaling without rotation
            if (direction === 'toLocal') {
                return {
                    x: (coords.x - container.posX) / 1000,
                    y: (coords.y - container.posY) / 1000,
                    z: (coords.z - container.posZ) / 1000
                };
            } else {
                return {
                    x: coords.x * 1000 + container.posX,
                    y: coords.y * 1000 + container.posY,
                    z: coords.z * 1000 + container.posZ
                };
            }
        }
        
        // Cache the result with timestamp for LRU cache management
        this.transformCache.set(cacheKey, { ...result });
        this.cacheTimestamps.set(cacheKey, Date.now());
        
        // Manage cache size
        this.pruneCache();
        
        return result;
    }
    
    /**
     * Get cache statistics for performance analysis
     */
    public static getCacheStats(): { hits: number, misses: number, size: number, hitRate: number } {
        const total = this.cacheHits + this.cacheMisses;
        const hitRate = total > 0 ? this.cacheHits / total : 0;
        
        return {
            hits: this.cacheHits,
            misses: this.cacheMisses,
            size: this.transformCache.size,
            hitRate: hitRate
        };
    }
    
    /**
     * Clear coordinate transformation cache (useful for testing)
     */
    public static clearCache(): void {
        this.transformCache.clear();
        this.cacheTimestamps.clear();
        this.cacheHits = 0;
        this.cacheMisses = 0;
        console.log("Coordinate transformation cache cleared");
    }
}