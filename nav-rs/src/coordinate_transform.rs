use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::types::{ObjectContainer, Quaternion, Vector3};

/// Specialized utility for coordinate transformations in space navigation systems
pub struct CoordinateTransformer {
    /// Cache for expensive coordinate transformations
    transform_cache: Mutex<HashMap<String, (Vector3, Instant)>>,
    
    /// Cache hit statistics
    cache_hits: Mutex<usize>,
    
    /// Cache miss statistics
    cache_misses: Mutex<usize>,
    
    /// Cache size limit
    cache_limit: usize,
    
    /// Cache prune threshold (percentage as a fraction)
    cache_prune_threshold: f64,
}

impl CoordinateTransformer {
    /// Create a new coordinate transformer with default cache settings
    pub fn new() -> Self {
        Self {
            transform_cache: Mutex::new(HashMap::with_capacity(2048)),
            cache_hits: Mutex::new(0),
            cache_misses: Mutex::new(0),
            cache_limit: 2048,
            cache_prune_threshold: 0.2, // Prune 20% of cache when limit reached
        }
    }
    
    /// Create a new coordinate transformer with custom cache settings
    pub fn with_cache_settings(cache_limit: usize, prune_threshold: f64) -> Self {
        Self {
            transform_cache: Mutex::new(HashMap::with_capacity(cache_limit)),
            cache_hits: Mutex::new(0),
            cache_misses: Mutex::new(0),
            cache_limit,
            cache_prune_threshold: prune_threshold,
        }
    }
    
    /// Get elapsed time since simulation start in days
    /// Uses January 1, 2020 as the simulation start date
    pub fn get_elapsed_utc_server_time(&self) -> f64 {
        // Simulation start date is January 1, 2020
        // Calculate timestamp for Jan 1, 2020 00:00:00 UTC
        let simulation_start = SystemTime::UNIX_EPOCH + Duration::from_secs(1577836800);
        
        // Get current time
        let current_time = SystemTime::now();
        
        // Calculate elapsed time
        let elapsed = current_time.duration_since(simulation_start)
            .unwrap_or_else(|_| Duration::from_secs(0));
        
        // Convert to days (86400 seconds per day)
        elapsed.as_secs_f64() / 86400.0
    }
    
    /// Generate a cache key with precision control to avoid float comparison issues
    fn generate_cache_key(&self, coords: &Vector3, container: &ObjectContainer, direction: &str) -> String {
        // Use fixed precision to prevent floating point comparison issues
        format!(
            "{:.6},{:.6},{:.6},{},{}",
            coords.x, coords.y, coords.z,
            container.name, direction
        )
    }
    
    /// Prune least recently used cache entries when cache size limit is reached
    fn prune_cache(&self) {
        let mut cache = self.transform_cache.lock().unwrap();
        
        if cache.len() <= self.cache_limit {
            return;
        }
        
        // Get all cache entries with their timestamps
        let mut entries: Vec<(String, Instant)> = cache.iter()
            .map(|(k, (_, ts))| (k.clone(), *ts))
            .collect();
        
        // Sort by timestamp (oldest first)
        entries.sort_by_key(|(_, ts)| *ts);
        
        // Calculate how many entries to remove
        let remove_count = (self.cache_limit as f64 * self.cache_prune_threshold).ceil() as usize;
        
        // Remove oldest entries
        for (key, _) in entries.iter().take(remove_count) {
            cache.remove(key);
        }
        
        log::info!("Pruned {} entries from coordinate transform cache", remove_count);
    }
    
    /// Transform coordinates between global and local reference frames
    /// Handles both global-to-local and local-to-global transformations
    pub fn transform_coordinates(
        &self,
        coords: &Vector3,
        container: &ObjectContainer,
        direction: TransformDirection,
    ) -> Vector3 {
        let dir_str = match direction {
            TransformDirection::ToGlobal => "toGlobal",
            TransformDirection::ToLocal => "toLocal",
        };
        
        // Generate cache key with precision control
        let cache_key = self.generate_cache_key(coords, container, dir_str);
        
        // Check cache first
        {
            let cache = self.transform_cache.lock().unwrap();
            if let Some((cached_result, _)) = cache.get(&cache_key) {
                // Update hit count
                let mut hits = self.cache_hits.lock().unwrap();
                *hits += 1;
                return *cached_result;
            }
        }
        
        // Update miss count
        {
            let mut misses = self.cache_misses.lock().unwrap();
            *misses += 1;
        }
        
        // Get elapsed time and calculate current rotation
        let elapsed_days = self.get_elapsed_utc_server_time();
        
        // Safety check for invalid rotation velocity
        let rot_vel_x = if container.rot_vel.x == 0.0 {
            log::warn!("Container {} has zero rotation velocity. Using dummy value.", container.name);
            24.0 // Assume 24-hour day as fallback
        } else {
            container.rot_vel.x
        };
        
        // Convert hours to day fraction
        let day_length_fraction = rot_vel_x * 3600.0 / 86400.0;
        
        // Calculate current rotation
        let total_rotations = elapsed_days / day_length_fraction;
        let current_rotation_fraction = total_rotations % 1.0;
        let current_rotation_degrees = current_rotation_fraction * 360.0;
        let absolute_rotation_degrees = container.rot_adj.x + current_rotation_degrees;
        
        // Create rotation quaternion for Z-axis planetary rotation
        let rotation_quat = Quaternion::from_euler(0.0, 0.0, absolute_rotation_degrees);
        let inverse_rotation_quat = rotation_quat.conjugate();
        
        let result = match direction {
            TransformDirection::ToLocal => {
                // Global to local transformation
                
                // Step 1: Translate to origin-centered coordinates
                let centered = Vector3::new(
                    coords.x - container.position.x,
                    coords.y - container.position.y,
                    coords.z - container.position.z,
                );
                
                // Step 2: Apply inverse rotation to get local coordinates
                let rotated = inverse_rotation_quat.rotate_vector(&centered);
                
                // Step 3: Scale to appropriate units (for display)
                Vector3::new(
                    rotated.x / 1000.0, // Convert to km for display
                    rotated.y / 1000.0,
                    rotated.z / 1000.0,
                )
            },
            TransformDirection::ToGlobal => {
                // Local to global transformation
                
                // Step 1: Scale to appropriate units (from display)
                let scaled = Vector3::new(
                    coords.x * 1000.0, // Convert from km to meters
                    coords.y * 1000.0,
                    coords.z * 1000.0,
                );
                
                // Step 2: Apply rotation to get global orientation
                let rotated = rotation_quat.rotate_vector(&scaled);
                
                // Step 3: Translate to global coordinates
                Vector3::new(
                    rotated.x + container.position.x,
                    rotated.y + container.position.y,
                    rotated.z + container.position.z,
                )
            }
        };
        
        // Verify result for NaN values
        if result.x.is_nan() || result.y.is_nan() || result.z.is_nan() {
            log::error!(
                "NaN detected in coordinate transformation: input: {:?}, container: {}, direction: {:?}, rotation: {}",
                coords, container.name, direction, absolute_rotation_degrees
            );
            
            // Fallback to direct scaling without rotation
            return match direction {
                TransformDirection::ToLocal => Vector3::new(
                    (coords.x - container.position.x) / 1000.0,
                    (coords.y - container.position.y) / 1000.0,
                    (coords.z - container.position.z) / 1000.0,
                ),
                TransformDirection::ToGlobal => Vector3::new(
                    coords.x * 1000.0 + container.position.x,
                    coords.y * 1000.0 + container.position.y,
                    coords.z * 1000.0 + container.position.z,
                ),
            };
        }
        
        // Cache the result with timestamp
        {
            let mut cache = self.transform_cache.lock().unwrap();
            cache.insert(cache_key, (result, Instant::now()));
            
            // Manage cache size
            if cache.len() > self.cache_limit {
                drop(cache); // Release the lock before pruning
                self.prune_cache();
            }
        }
        
        result
    }
    
    /// Get cache statistics for performance analysis
    pub fn get_cache_stats(&self) -> CacheStats {
        let hits = *self.cache_hits.lock().unwrap();
        let misses = *self.cache_misses.lock().unwrap();
        let total = hits + misses;
        let hit_rate = if total > 0 { hits as f64 / total as f64 } else { 0.0 };
        let size = self.transform_cache.lock().unwrap().len();
        
        CacheStats {
            hits,
            misses,
            size,
            hit_rate,
        }
    }
    
    /// Clear coordinate transformation cache
    pub fn clear_cache(&self) {
        let mut cache = self.transform_cache.lock().unwrap();
        cache.clear();
        
        let mut hits = self.cache_hits.lock().unwrap();
        *hits = 0;
        
        let mut misses = self.cache_misses.lock().unwrap();
        *misses = 0;
        
        log::info!("Coordinate transformation cache cleared");
    }
}

impl Default for CoordinateTransformer {
    fn default() -> Self {
        Self::new()
    }
}

/// Direction for coordinate transformation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformDirection {
    ToGlobal,
    ToLocal,
}

/// Cache statistics structure
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    pub size: usize,
    pub hit_rate: f64,
}