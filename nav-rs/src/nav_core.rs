use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::coordinate_transform::{CoordinateTransformer, TransformDirection};
use crate::types::{
    AstronomicalDataProvider, ContainerType, EulerAngles, LineOfSightResult, NamedDistance,
    NavNodeType, NavigationResult, ObjectContainer, PointOfInterest, Vector3,
};

/// Core navigation functionality for the space navigation system
pub struct NavigationCore<T: AstronomicalDataProvider> {
    pub data_provider: Arc<T>,
    pub transformer: CoordinateTransformer,
    pub current_position: Option<Vector3>,
    pub previous_position: Option<Vector3>,
    pub position_timestamp: u64,
    pub previous_timestamp: u64,
    pub selected_poi: Option<usize>,
    pub current_object_container: Option<usize>,
}

impl<T: AstronomicalDataProvider> NavigationCore<T> {
    /// Create a new navigation core with the given data provider
    pub fn new(data_provider: Arc<T>) -> Self {
        Self {
            data_provider,
            transformer: CoordinateTransformer::new(),
            current_position: None,
            previous_position: None,
            position_timestamp: 0,
            previous_timestamp: 0,
            selected_poi: None,
            current_object_container: None,
        }
    }

    /// Calculate 3D Euclidean distance between two points
    pub fn calc_distance_3d(&self, p1: &Vector3, p2: &Vector3) -> f64 {
        ((p1.x - p2.x).powi(2) + (p1.y - p2.y).powi(2) + (p1.z - p2.z).powi(2)).sqrt()
    }

    /// Update current player position
    pub fn update_position(&mut self, x: f64, y: f64, z: f64) {
        // Store previous position for velocity calculation
        if let Some(pos) = self.current_position {
            self.previous_position = Some(pos);
            self.previous_timestamp = self.position_timestamp;
        }

        self.current_position = Some(Vector3::new(x, y, z));
        self.position_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64;

        // Detect current object container (planet/moon)
        self.detect_current_object_container();
    }

    /// Determine which celestial body the player is near/on
    fn detect_current_object_container(&mut self) {
        let current_position = match self.current_position {
            Some(pos) => pos,
            None => return,
        };

        self.current_object_container = None;

        for (i, container) in self.data_provider.get_object_containers().iter().enumerate() {
            let distance = self.calc_distance_3d(
                &current_position,
                &container.position,
            );

            // If within the orbital marker radius * 1.5, consider player to be within this container
            if distance <= container.om_radius * 1.5 {
                self.current_object_container = Some(i);
                break;
            }
        }
    }

    /// Select a point of interest by ID
    pub fn select_poi(&mut self, poi_id: u32) -> Option<&PointOfInterest> {
        let pois = self.data_provider.get_points_of_interest();
        
        // Find POI by ID
        let index = pois.iter().position(|p| p.id == poi_id);
        
        self.selected_poi = index;
        
        if let Some(idx) = index {
            Some(&pois[idx])
        } else {
            None
        }
    }
    
    /// Select a point of interest by name
    pub fn select_poi_by_name(&mut self, name: &str) -> Option<&PointOfInterest> {
        let pois = self.data_provider.get_points_of_interest();
        
        // Find POI by name
        let index = pois.iter().position(|p| p.name == name);
        
        self.selected_poi = index;
        
        if let Some(idx) = index {
            Some(&pois[idx])
        } else {
            None
        }
    }

    /// Calculate velocity vector based on position changes
    fn calculate_velocity(&self) -> Option<Vector3> {
        match (self.current_position, self.previous_position) {
            (Some(current), Some(previous)) => {
                if self.position_timestamp == self.previous_timestamp {
                    return None;
                }

                let time_delta = (self.position_timestamp - self.previous_timestamp) as f64 / 1000.0; // in seconds

                Some(Vector3::new(
                    (current.x - previous.x) / time_delta,
                    (current.y - previous.y) / time_delta,
                    (current.z - previous.z) / time_delta,
                ))
            }
            _ => None,
        }
    }

    /// Get elapsed time since simulation start in days
    fn get_elapsed_utc_server_time(&self) -> f64 {
        self.transformer.get_elapsed_utc_server_time()
    }

    /// Calculate Euler angles for direction from current position to destination
    fn calculate_euler_angles(&self, current: &Vector3, destination: &Vector3) -> EulerAngles {
        // Calculate deltas between current and destination positions
        let dx = destination.x - current.x;
        let dy = destination.y - current.y;
        let dz = destination.z - current.z;

        // Calculate distance in the XY plane
        let distance_xy = (dx * dx + dy * dy).sqrt();

        // Calculate pitch (vertical angle)
        let pitch = (dz / distance_xy).atan() * (180.0 / std::f64::consts::PI);

        // Roll is 0 for simplicity
        let roll = 0.0;

        // Calculate yaw (horizontal angle)
        let mut yaw = (dy / dx).atan() * (180.0 / std::f64::consts::PI);

        // Convert to game's coordinate system
        if yaw > 90.0 {
            yaw = yaw - 270.0;
        } else {
            yaw = yaw + 90.0;
        }

        EulerAngles::new(pitch, yaw, roll)
    }

    /// Calculate angular deviation between current trajectory and destination
    fn calculate_angular_deviation(
        &self,
        prev_pos: &Vector3,
        current_pos: &Vector3,
        dest_pos: &Vector3,
    ) -> f64 {
        // Vector from previous to current position = current trajectory
        let vx = current_pos.x - prev_pos.x;
        let vy = current_pos.y - prev_pos.y;
        let vz = current_pos.z - prev_pos.z;

        // Vector from current to destination
        let dx = dest_pos.x - current_pos.x;
        let dy = dest_pos.y - current_pos.y;
        let dz = dest_pos.z - current_pos.z;

        // Calculate dot product
        let dot_product = vx * dx + vy * dy + vz * dz;

        // Calculate magnitudes
        let v_mag = (vx * vx + vy * vy + vz * vz).sqrt();
        let d_mag = (dx * dx + dy * dy + dz * dz).sqrt();

        // Safety check to avoid division by zero
        if v_mag < 1e-6 || d_mag < 1e-6 {
            return 0.0;
        }

        // Calculate angle in radians and convert to degrees
        (dot_product / (v_mag * d_mag)).acos() * (180.0 / std::f64::consts::PI)
    }

    /// Find closest orbital marker to a position on a planet
    fn find_closest_orbital_marker(
        &self,
        position: &Vector3,
        container: &ObjectContainer,
    ) -> NamedDistance {
        // Base implementation assumes no orbital markers data
        // Subclasses should override this with actual implementation
        log::warn!("Base implementation called for {}", container.name);
        
        NamedDistance {
            name: "OM-3".to_string(), // Placeholder
            distance: 100000.0,
        }
    }

    /// Find closest QT beacon to a position
    fn find_closest_qt_beacon(&self, position: &Vector3) -> Option<NamedDistance> {
        let pois = self.data_provider.get_points_of_interest();
        if pois.is_empty() {
            return None;
        }

        let mut closest_beacon = None;
        let mut min_distance = f64::MAX;

        // Loop through all POIs with QT markers
        for poi in pois.iter().filter(|p| p.has_qt_marker) {
            let poi_pos = self.get_global_coordinates(poi);
            let distance = self.calc_distance_3d(position, &poi_pos);

            if distance < min_distance {
                min_distance = distance;
                closest_beacon = Some(NamedDistance {
                    name: poi.name.clone(),
                    distance,
                });
            }
        }

        closest_beacon
    }

    /// Calculate ETA based on current velocity and distance
    fn calculate_eta(&self, distance: f64, velocity: &Vector3) -> f64 {
        // Calculate speed (magnitude of velocity vector)
        let speed = (velocity.x * velocity.x + velocity.y * velocity.y + velocity.z * velocity.z).sqrt();

        // If not moving or moving away, return -1
        if speed <= 0.0 {
            return -1.0;
        }

        // Return ETA in seconds
        distance / speed
    }

    /// Get global coordinates for a POI
    fn get_global_coordinates(&self, poi: &PointOfInterest) -> Vector3 {
        // If the POI has a QT marker or no container, it's already in global coords
        if poi.has_qt_marker || poi.obj_container.is_none() {
            return poi.position;
        }

        // Find the container
        let containers = self.data_provider.get_object_containers();
        let container_opt = poi.obj_container.as_ref().and_then(|container_name| {
            containers.iter().find(|c| c.name == *container_name)
        });

        // If container not found, return position as is (as a fallback)
        let container = match container_opt {
            Some(c) => c,
            None => {
                log::error!("Container not found for POI: {}", poi.name);
                return poi.position;
            }
        };

        // Transform local coordinates to global
        self.transformer.transform_coordinates(
            &poi.position,
            container,
            TransformDirection::ToGlobal,
        )
    }

    /// Calculate coordinates accounting for planetary rotation
    fn calculate_rotated_planetary_coordinates(
        &self,
        local_coords: &Vector3,
        container: &ObjectContainer,
    ) -> Vector3 {
        // Get elapsed time and calculate rotation angle based on rotVelX
        let elapsed_utc_time_since_simulation_start = self.get_elapsed_utc_server_time();
        let length_of_day_decimal = container.rot_vel.x * 3600.0 / 86400.0;
        let total_cycles = elapsed_utc_time_since_simulation_start / length_of_day_decimal;
        let current_cycle_dez = total_cycles % 1.0;
        let current_cycle_deg = current_cycle_dez * 360.0;
        let current_cycle_angle = container.rot_adj.x + current_cycle_deg;

        // Calculate rotation with precise angular transform
        let angle_rad = current_cycle_angle * std::f64::consts::PI / 180.0;

        // Apply rotation matrix to the local coordinates
        let rot_x = local_coords.x * angle_rad.cos() - local_coords.y * angle_rad.sin();
        let rot_y = local_coords.x * angle_rad.sin() + local_coords.y * angle_rad.cos();

        // Transform back to global coordinate system by adding planet position
        Vector3::new(
            container.position.x + rot_x * 1000.0, // Convert back to meters
            container.position.y + rot_y * 1000.0,
            container.position.z + local_coords.z * 1000.0,
        )
    }

    /// Convert system coordinates to non-rotated static coordinates
    /// This function reverses the planetary rotation to get static coordinates
    pub fn convert_to_static_coordinates(
        &self,
        global_pos: &Vector3,
        container: &ObjectContainer,
    ) -> Vector3 {
        // Check if container is valid to prevent NaN results
        if container.rot_vel.x == 0.0 {
            log::warn!("Invalid container or zero rotation velocity");
            return *global_pos; // Return copy of input to avoid NaN
        }

        // Calculate difference vectors (ECEF coordinate system)
        let dx = global_pos.x - container.position.x;
        let dy = global_pos.y - container.position.y;
        let dz = global_pos.z - container.position.z;

        // Get elapsed time and calculate rotation angle
        let elapsed_utc_time_since_simulation_start = self.get_elapsed_utc_server_time();
        let length_of_day_decimal = container.rot_vel.x * 3600.0 / 86400.0; // Convert hours to day fraction
        
        // Prevent division by zero
        if length_of_day_decimal == 0.0 {
            log::warn!("Length of day decimal is zero, cannot calculate rotation");
            return *global_pos;
        }
        
        let total_cycles = elapsed_utc_time_since_simulation_start / length_of_day_decimal;
        let current_cycle_dez = total_cycles % 1.0;
        let current_cycle_deg = current_cycle_dez * 360.0;
        let current_cycle_angle = container.rot_adj.x + current_cycle_deg;

        // Convert angle to radians
        let angle_rad = current_cycle_angle * std::f64::consts::PI / 180.0;

        // Apply inverse rotation matrix to transform from rotated to static coordinates
        // We use the negative angle to reverse the rotation
        let static_x = dx * (-angle_rad).cos() - dy * (-angle_rad).sin();
        let static_y = dx * (-angle_rad).sin() + dy * (-angle_rad).cos();

        // Return the static coordinates relative to the container's position
        let result = Vector3::new(
            container.position.x + static_x,
            container.position.y + static_y,
            container.position.z + dz,
        );
        
        // Debug output to help diagnose NaN issues
        if result.x.is_nan() || result.y.is_nan() || result.z.is_nan() {
            log::error!(
                "NaN detected in convertToStaticCoordinates: input: {:?}, container: {:?}, angle_rad: {}, dx: {}, dy: {}, dz: {}, static_x: {}, static_y: {}",
                global_pos, container, angle_rad, dx, dy, dz, static_x, static_y
            );
        }
        
        result
    }

    /// Get comprehensive navigation data to selected POI
    pub fn get_navigation_data(&self) -> Option<NavigationResult> {
        // Ensure we have a current position and selected POI
        let current_position = self.current_position?;
        let selected_poi_idx = self.selected_poi?;
        let poi = &self.data_provider.get_points_of_interest()[selected_poi_idx];
        
        // Get destination coordinates
        let mut destination_coords = self.get_global_coordinates(poi);
        
        // If POI is on a planet, adjust for planetary rotation
        if let Some(obj_container) = &poi.obj_container {
            let containers = self.data_provider.get_object_containers();
            if let Some(poi_container) = containers.iter().find(|c| &c.name == obj_container) {
                // The actual coordinates would need to be calculated with the planet's current rotation
                destination_coords = self.calculate_rotated_planetary_coordinates(
                    &self.get_global_coordinates(poi),
                    poi_container,
                );
            }
        }
        
        // Calculate distance
        let distance = self.calc_distance_3d(&current_position, &destination_coords);
        
        // Calculate direction
        let direction = self.calculate_euler_angles(&current_position, &destination_coords);
        
        // Calculate angular deviation if we have a previous position
        let angular_deviation = self.previous_position.map(|prev_pos| {
            self.calculate_angular_deviation(
                &prev_pos,
                &current_position,
                &destination_coords,
            )
        });
        
        // Calculate velocity and ETA
        let velocity = self.calculate_velocity();
        let eta = velocity.map_or(-1.0, |vel| self.calculate_eta(distance, &vel));
        
        // Get closest orbital marker if on a planet
        let closest_orbital_marker = self.current_object_container.map(|idx| {
            let container = &self.data_provider.get_object_containers()[idx];
            self.find_closest_orbital_marker(&current_position, container)
        });
        
        // Get closest QT beacon
        let closest_qt_beacon = self.find_closest_qt_beacon(&current_position);
        
        // Create the NavigationResult
        Some(NavigationResult {
            distance,
            direction,
            eta,
            angular_deviation,
            closest_orbital_marker,
            closest_qt_beacon,
        })
    }
    
    /// Check for line of sight between two points
    pub fn check_line_of_sight(&self, from: &Vector3, to: &Vector3) -> LineOfSightResult {
        // Vector between positions
        let dx = to.x - from.x;
        let dy = to.y - from.y;
        let dz = to.z - from.z;
        
        // Distance between points
        let distance = (dx * dx + dy * dy + dz * dz).sqrt();
        
        // Direction vector (normalized)
        let dir_x = dx / distance;
        let dir_y = dy / distance;
        let dir_z = dz / distance;
        
        // Check each celestial body for intersection
        for container in self.data_provider.get_object_containers() {
            // Skip non-physical objects
            if container.body_radius <= 0.0 {
                continue;
            }
            
            // Skip bodies that are in different star systems
            if let Some(current_container_idx) = self.current_object_container {
                let current_container = &self.data_provider.get_object_containers()[current_container_idx];
                if container.system != current_container.system {
                    continue;
                }
            }
            
            // Vector from origin to sphere center
            let oc_x = container.position.x - from.x;
            let oc_y = container.position.y - from.y;
            let oc_z = container.position.z - from.z;
            
            // Projection of oc onto the ray direction
            let proj_oc = oc_x * dir_x + oc_y * dir_y + oc_z * dir_z;
            
            // If negative, sphere is behind the ray origin
            if proj_oc < 0.0 && (oc_x * oc_x + oc_y * oc_y + oc_z * oc_z) > container.body_radius * container.body_radius {
                continue;
            }
            
            // Squared distance from sphere center to ray
            let dist_sq = (oc_x * oc_x + oc_y * oc_y + oc_z * oc_z) - (proj_oc * proj_oc);
            let radius_sq = container.body_radius * container.body_radius;
            
            // If this distance > radius, no intersection
            if dist_sq > radius_sq {
                continue;
            }
            
            // Distance from projection to intersection points
            let intersect_dist = (radius_sq - dist_sq).sqrt();
            
            // Calculate first intersection distance
            let intersect1 = proj_oc - intersect_dist;
            let intersect2 = proj_oc + intersect_dist;
            
            // If either intersection point is within our segment length, we have obstruction
            if (intersect1 > 0.0 && intersect1 < distance) || (intersect2 > 0.0 && intersect2 < distance) {
                return LineOfSightResult {
                    has_los: false,
                    obstruction: Some(Arc::new(container.clone())),
                };
            }
        }
        
        // No obstructions found
        LineOfSightResult {
            has_los: true,
            obstruction: None,
        }
    }
    
    /// Get the current object container
    pub fn get_current_object_container(&self) -> Option<&ObjectContainer> {
        self.current_object_container.map(|idx| {
            &self.data_provider.get_object_containers()[idx]
        })
    }
    
    /// Get the current position
    pub fn get_current_position(&self) -> Option<Vector3> {
        self.current_position
    }
    
    /// Find nearby Points of Interest for contextual awareness
    pub fn find_nearby_pois(&self, limit: usize) -> Vec<NamedDistance> {
        let position = match self.current_position {
            Some(pos) => pos,
            None => return Vec::new(),
        };
        
        let mut pois_with_distances: Vec<NamedDistance> = self.data_provider
            .get_points_of_interest()
            .iter()
            .map(|poi| {
                let poi_coords = self.get_global_coordinates(poi);
                NamedDistance {
                    name: poi.name.clone(),
                    distance: self.calc_distance_3d(&position, &poi_coords) / 1000.0, // Convert to km
                }
            })
            .collect();
        
        // Sort by distance (ascending)
        pois_with_distances.sort_by(|a, b| a.distance.partial_cmp(&b.distance).unwrap_or(std::cmp::Ordering::Equal));
        
        // Return the closest POIs
        pois_with_distances.truncate(limit);
        pois_with_distances
    }

    /// Resolve which container (planet/moon) a position is located within
    pub fn resolve_container_at_position(&self, position: &Vector3) -> Option<ObjectContainer> {
        for container in self.data_provider.get_object_containers() {
            // Skip non-physical objects or containers with no meaningful radius
            if container.body_radius <= 0.0 {
                continue;
            }
            
            // Calculate distance from position to container center
            let distance = self.calc_distance_3d(position, &container.position);
            
            // If position is within the body radius (with a small buffer for atmosphere approximation)
            // Use 1.05 as a multiplier to give a small buffer around the body
            let effective_radius = container.body_radius * 1.05;
            
            if distance <= effective_radius {
                return Some(container.clone());
            }
        }
        
        // Position isn't within any container
        None
    }
}