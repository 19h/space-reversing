use crate::types::{ObjectContainer, Quaternion, Vector3};
use std::time::{Duration, SystemTime};
use std::f64::consts::PI;

/// Specialized utility for coordinate transformations in space navigation systems
pub struct CoordinateTransformer {}

impl CoordinateTransformer {
    /// Create a new coordinate transformer
    pub fn new() -> Self {
        Self {}
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
    
    /// Transform coordinates between global and local reference frames
    /// Handles both global-to-local and local-to-global transformations
    pub fn transform_coordinates(
        &self,
        coords: &Vector3,
        container: &ObjectContainer,
        direction: TransformDirection,
    ) -> Vector3 {
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
        
        result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContainerType, ObjectContainer, Quaternion, System, Vector3};
    use std::f64::consts::PI;

    /// Create a test container for coordinate transformation tests
    fn create_test_container() -> ObjectContainer {
        ObjectContainer {
            id: 1,
            system: System::Stanton,
            container_type: ContainerType::Planet,
            name: "TestPlanet".to_string(),
            internal_name: "test_planet".to_string(),
            position: Vector3::new(1000000.0, 2000000.0, 3000000.0),
            rot_vel: Vector3::new(0.1, 0.0, 0.0),
            rot_adj: Vector3::new(0.0, 0.0, 0.0),
            rot_quat: Quaternion::new(1.0, 0.0, 0.0, 0.0),
            body_radius: 500000.0,
            om_radius: 600000.0,
            grid_radius: 700000.0,
        }
    }
    
    // Mock the time for deterministic testing
    struct MockCoordinateTransformer {
        fixed_elapsed_days: f64
    }
    
    impl MockCoordinateTransformer {
        fn new(fixed_elapsed_days: f64) -> Self {
            Self { fixed_elapsed_days }
        }
        
        fn get_elapsed_utc_server_time(&self) -> f64 {
            self.fixed_elapsed_days
        }
        
        // Copy the transform_coordinates method but use the fixed time
        fn transform_coordinates(
            &self,
            coords: &Vector3,
            container: &ObjectContainer,
            direction: TransformDirection,
        ) -> Vector3 {
            // Use fixed elapsed time instead of actual time
            let elapsed_days = self.fixed_elapsed_days;
            
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
            
            result
        }
    }
    
    #[test]
    fn test_transform_coordinates_roundtrip() {
        // Use fixed time for deterministic testing
        let mock_transformer = MockCoordinateTransformer::new(42.0);
        let container = create_test_container();
        
        // Original local coordinates (in km)
        let original_local = Vector3::new(123.456, 789.012, 345.678);
        
        // Transform to global
        let global = mock_transformer.transform_coordinates(
            &original_local,
            &container,
            TransformDirection::ToGlobal,
        );
        
        // Transform back to local
        let local_again = mock_transformer.transform_coordinates(
            &global,
            &container,
            TransformDirection::ToLocal,
        );
        
        // Should get back the original coordinates
        assert!((local_again.x - original_local.x).abs() < 0.001, 
            "X coordinate roundtrip failed: {} vs {}", local_again.x, original_local.x);
        assert!((local_again.y - original_local.y).abs() < 0.001,
            "Y coordinate roundtrip failed: {} vs {}", local_again.y, original_local.y);
        assert!((local_again.z - original_local.z).abs() < 0.001,
            "Z coordinate roundtrip failed: {} vs {}", local_again.z, original_local.z);
    }
    
    // Additional tests using the mock transformer...
}
