//! Space Navigation System
//!
//! A comprehensive navigation system for celestial navigation with advanced
//! pathfinding, quaternion-based coordinate transformations, and collision detection.
//! Implements optimized bidirectional A* search with pre-computed visibility graphs.

extern crate log;

pub mod types;
pub mod coordinate_transform;
pub mod nav_core;
pub mod nav_planner;
pub mod data_loader;

use std::sync::Arc;

pub use coordinate_transform::CoordinateTransformer;
pub use nav_planner::NavigationPlanner;
pub use types::{AstronomicalDataProvider, NavigationPlan, PointOfInterest, ObjectContainer, StaticAstronomicalData};

pub use types::NamedDistance;

/// Navigation system for interplanetary travel calculations
pub struct SpaceNavigationSystem<T: AstronomicalDataProvider> {
    pub planner: NavigationPlanner<T>,
    pub data_provider: Arc<T>,
}

impl<T: AstronomicalDataProvider> SpaceNavigationSystem<T> {
    /// Create a new space navigation system with the given data provider
    pub fn new(data_provider: T) -> Self {
        let data_provider = Arc::new(data_provider);
        let planner = NavigationPlanner::new(Arc::clone(&data_provider));
        
        Self {
            planner,
            data_provider,
        }
    }
    
    /// Set current position using local coordinates relative to an object container
    pub fn set_position_local(&mut self, container_name: &str, local_x: f64, local_y: f64, local_z: f64) {
        self.planner.set_position_local(container_name, local_x, local_y, local_z);
    }
    
    /// Update position with absolute coordinates
    pub fn update_position(&mut self, x: f64, y: f64, z: f64) {
        self.planner.update_position(x, y, z);
    }
    
    /// Plan navigation to a destination
    pub fn plan_navigation(&self, destination_name: &str) -> Option<NavigationPlan> {
        self.planner.plan_navigation(destination_name)
    }
    
    /// Format navigation plan as human-readable instructions
    pub fn format_navigation_instructions(&self, plan: &NavigationPlan) -> String {
        self.planner.format_navigation_instructions(plan)
    }
    
    /// Find nearby points of interest
    pub fn find_nearby_pois(&self, limit: usize) -> Vec<types::NamedDistance> {
        self.planner.find_nearby_pois(limit)
    }
    
    /// Plan navigation to specific coordinates, either global or relative to a container
    pub fn plan_navigation_to_coordinates(
        &self, 
        container_name: Option<&str>, 
        pos_x: f64, 
        pos_y: f64, 
        pos_z: f64
    ) -> Option<NavigationPlan> {
        self.planner.plan_navigation_to_coordinates(container_name, pos_x, pos_y, pos_z)
    }
    
    /// Determine current solar system
    pub fn get_current_solar_system(&self, plan: Option<&NavigationPlan>) -> types::System {
        self.planner.determine_current_solar_system(plan)
    }
    
    /// Get the current position if available
    pub fn get_current_position(&self) -> Option<types::Vector3> {
        self.planner.core.get_current_position()
    }
    
    /// Get the current object container (planet/moon/station) if available
    pub fn get_current_object_container(&self) -> Option<types::ObjectContainer> {
        self.planner.core.get_current_object_container().cloned()
    }
    
    /// Find nearby points of interest within a specific radius
    pub fn find_nearby_pois_in_radius(&self, radius: f64) -> Vec<types::NamedDistance> {
        self.planner.find_nearby_pois_in_radius(radius)
    }
}

/// Create a navigation system from predefined objects and POIs
pub fn create_navigation_system(poi_data: Vec<PointOfInterest>, container_data: Vec<types::ObjectContainer>) -> SpaceNavigationSystem<StaticAstronomicalData> {
    let data_provider = StaticAstronomicalData::new(poi_data, container_data);
    SpaceNavigationSystem::new(data_provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContainerType, PoiType, Quaternion, System, Vector3};
    
    /// Create a minimal set of test objects for navigation testing
    fn create_test_data() -> (Vec<PointOfInterest>, Vec<types::ObjectContainer>) {
        // Create a few planets and moons
        let containers = vec![
            // Planet: Hurston
            types::ObjectContainer {
                id: 1,
                system: System::Stanton,
                container_type: ContainerType::Planet,
                name: "Hurston".to_string(),
                internal_name: "Stanton1".to_string(),
                position: Vector3::new(12875442280.0, 0.0, 0.0),
                rot_vel: Vector3::new(5.0, 0.0, 0.0),
                rot_adj: Vector3::new(0.0, 0.0, 0.0),
                rot_quat: Quaternion::new(1.0, 0.0, 0.0, 0.0),
                body_radius: 1000000.0,
                om_radius: 1500000.0,
                grid_radius: 2000000.0,
            },
            // Moon: Daymar
            types::ObjectContainer {
                id: 2,
                system: System::Stanton,
                container_type: ContainerType::Moon,
                name: "Daymar".to_string(),
                internal_name: "Stanton2b".to_string(), 
                position: Vector3::new(-18930539540.0, -2610158765.0, 0.0),
                rot_vel: Vector3::new(2.48, 0.0, 0.0),
                rot_adj: Vector3::new(188.35, 0.0, 0.0),
                rot_quat: Quaternion::new(1.0, 0.0, 0.0, 0.0),
                body_radius: 295000.0,
                om_radius: 432850.0,
                grid_radius: 590000.0,
            },
            // Planet: Microtech
            types::ObjectContainer {
                id: 3,
                system: System::Stanton,
                container_type: ContainerType::Planet,
                name: "MicroTech".to_string(),
                internal_name: "Stanton4".to_string(),
                position: Vector3::new(22462085252.0, 37185744964.0, 0.0),
                rot_vel: Vector3::new(4.12, 0.0, 0.0),
                rot_adj: Vector3::new(248.2, 0.0, 0.0),
                rot_quat: Quaternion::new(1.0, 0.0, 0.0, 0.0),
                body_radius: 1000000.0,
                om_radius: 1439593.0,
                grid_radius: 2300000.0,
            },
        ];
        
        // Create a few POIs
        let pois = vec![
            // Shubin Mining Facility SCD-1 (on Daymar)
            types::PointOfInterest {
                id: 1,
                name: "Shubin Mining Facility SCD-1".to_string(),
                system: "Stanton".to_string(),
                obj_container: Some("Daymar".to_string()),
                poi_type: PoiType::Outpost,
                class: "Mining".to_string(),
                position: Vector3::new(177.76, -145.73, 0.0),
                has_qt_marker: true,
                date_added: Some("2020-01-01".to_string()),
                comment: None,
                with_version: Some("3.0.0".to_string()),
            },
            // Lorville (on Hurston)
            types::PointOfInterest {
                id: 2,
                name: "Lorville".to_string(),
                system: "Stanton".to_string(),
                obj_container: Some("Hurston".to_string()),
                poi_type: PoiType::LandingZone,
                class: "City".to_string(),
                position: Vector3::new(-328.91, -785.98, 564.17),
                has_qt_marker: true,
                date_added: Some("2020-01-01".to_string()),
                comment: None,
                with_version: Some("3.0.0".to_string()),
            },
            // New Babbage (on Microtech)
            types::PointOfInterest {
                id: 3,
                name: "New Babbage".to_string(),
                system: "Stanton".to_string(),
                obj_container: Some("MicroTech".to_string()),
                poi_type: PoiType::LandingZone,
                class: "City".to_string(),
                position: Vector3::new(14.65, -337.45, 956.23),
                has_qt_marker: true,
                date_added: Some("2020-01-01".to_string()),
                comment: None,
                with_version: Some("3.4.0".to_string()),
            },
        ];
        
        (pois, containers)
    }
    
    #[test]
    fn test_navigation_plan() {
        // Create test data and navigation system
        let (pois, containers) = create_test_data();
        let mut nav_system = create_navigation_system(pois, containers);
        
        // Set current position at Lorville
        nav_system.set_position_local("Hurston", -328.91, -785.98, 564.17);
        
        // Plan navigation to Shubin Mining Facility
        let plan = nav_system.plan_navigation("Shubin Mining Facility SCD-1");
        
        // Verify that we got a valid plan
        assert!(plan.is_some(), "Navigation plan should be created successfully");
        
        let plan = plan.unwrap();
        
        // Verify basic plan properties
        assert!(!plan.segments.is_empty(), "Plan should have at least one segment");
        assert!(plan.total_distance > 0.0, "Total distance should be positive");
        assert!(plan.total_estimated_time > 0.0, "Estimated time should be positive");
        
        // Print navigation instructions
        let instructions = nav_system.format_navigation_instructions(&plan);
        println!("{}", instructions);
        
        // Verify that instructions contain segments
        assert!(instructions.contains("ROUTE SEGMENTS"), "Instructions should include route segments");
    }
}
