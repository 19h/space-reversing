use std::collections::HashMap;
use std::sync::Arc;
use std::fmt;

use serde::{Deserialize, Serialize};

/// 3D vector representation
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Vector3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vector3 {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub fn distance(&self, other: &Vector3) -> f64 {
        ((self.x - other.x).powi(2) + 
         (self.y - other.y).powi(2) + 
         (self.z - other.z).powi(2)).sqrt()
    }
    
    pub fn normalized(&self) -> Self {
        let magnitude = (self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt();
        if magnitude < 1e-6 {
            return *self; // Return unchanged if near-zero magnitude
        }
        Self {
            x: self.x / magnitude,
            y: self.y / magnitude,
            z: self.z / magnitude,
        }
    }
}

/// Quaternion representation for rotations
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Quaternion {
    pub w: f64,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Quaternion {
    pub fn new(w: f64, x: f64, y: f64, z: f64) -> Self {
        Self { w, x, y, z }
    }
    
    pub fn identity() -> Self {
        Self { w: 1.0, x: 0.0, y: 0.0, z: 0.0 }
    }
    
    pub fn conjugate(&self) -> Self {
        Self {
            w: self.w,
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
    
    pub fn normalize(&self) -> Self {
        let magnitude = (self.w.powi(2) + self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt();
        Self {
            w: self.w / magnitude,
            x: self.x / magnitude,
            y: self.y / magnitude,
            z: self.z / magnitude,
        }
    }
    
    pub fn multiply(&self, other: &Quaternion) -> Self {
        Self {
            w: self.w * other.w - self.x * other.x - self.y * other.y - self.z * other.z,
            x: self.w * other.x + self.x * other.w + self.y * other.z - self.z * other.y,
            y: self.w * other.y - self.x * other.z + self.y * other.w + self.z * other.x,
            z: self.w * other.z + self.x * other.y - self.y * other.x + self.z * other.w,
        }
    }
    
    pub fn rotate_vector(&self, vector: &Vector3) -> Vector3 {
        // Convert vector to quaternion form (0, vx, vy, vz)
        let vec_quat = Quaternion::new(0.0, vector.x, vector.y, vector.z);
        
        // Perform rotation: q * v * q^-1
        let result = self.multiply(&vec_quat).multiply(&self.conjugate());
        
        Vector3::new(result.x, result.y, result.z)
    }
    
    /// Convert Euler angles (in degrees) to quaternion
    pub fn from_euler(pitch: f64, yaw: f64, roll: f64) -> Self {
        // Convert to radians
        let pitch_rad = pitch.to_radians();
        let yaw_rad = yaw.to_radians();
        let roll_rad = roll.to_radians();
        
        // Calculate half angles
        let cx = (pitch_rad / 2.0).cos();
        let sx = (pitch_rad / 2.0).sin();
        let cy = (yaw_rad / 2.0).cos();
        let sy = (yaw_rad / 2.0).sin();
        let cz = (roll_rad / 2.0).cos();
        let sz = (roll_rad / 2.0).sin();
        
        // ZYX convention for Euler to quaternion conversion
        let w = cx * cy * cz + sx * sy * sz;
        let x = sx * cy * cz - cx * sy * sz;
        let y = cx * sy * cz + sx * cy * sz;
        let z = cx * cy * sz - sx * sy * cz;
        
        Self { w, x, y, z }.normalize()
    }
    
    /// Convert quaternion to Euler angles (in degrees)
    pub fn to_euler(&self) -> (f64, f64, f64) {
        // Normalize the quaternion to ensure valid results
        let q = self.normalize();
        
        // Extract Euler angles using ZYX convention (to match from_euler)
        
        // Pitch (X-axis rotation)
        let sinp = 2.0 * (q.w * q.x + q.y * q.z);
        let cosp = 1.0 - 2.0 * (q.x * q.x + q.y * q.y);
        let pitch = sinp.atan2(cosp);
        
        // Yaw (Y-axis rotation)
        let siny = 2.0 * (q.w * q.y - q.z * q.x);
        let yaw = if siny.abs() >= 1.0 {
            std::f64::consts::FRAC_PI_2.copysign(siny) // Use 90 degrees if out of range
        } else {
            siny.asin()
        };
        
        // Roll (Z-axis rotation)
        let sinr = 2.0 * (q.w * q.z + q.x * q.y);
        let cosr = 1.0 - 2.0 * (q.y * q.y + q.z * q.z);
        let roll = sinr.atan2(cosr);
        
        // Convert to degrees
        (
            pitch.to_degrees(),
            yaw.to_degrees(),
            roll.to_degrees()
        )
    }
}

/// Euler angles in degrees
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EulerAngles {
    pub pitch: f64,
    pub yaw: f64,
    pub roll: f64,
}

impl EulerAngles {
    pub fn new(pitch: f64, yaw: f64, roll: f64) -> Self {
        Self { pitch, yaw, roll }
    }
}

/// Solar system identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum System {
    Stanton,
    Pyro,
    Nyx, 
    Ellis,
    Sol,
    // Add other star systems as needed
}

impl System {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Stanton" => Some(System::Stanton),
            "Pyro" => Some(System::Pyro),
            "Nyx" => Some(System::Nyx),
            "Ellis" => Some(System::Ellis),
            "Sol" => Some(System::Sol),
            _ => None,
        }
    }
}

impl fmt::Display for System {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            System::Stanton => write!(f, "Stanton"),
            System::Pyro => write!(f, "Pyro"),
            System::Nyx => write!(f, "Nyx"),
            System::Ellis => write!(f, "Ellis"),
            System::Sol => write!(f, "Sol"),
        }
    }
}

/// Container type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerType {
    JumpPoint,
    Lagrange,
    Moon,
    NavalStation,
    Planet,
    RefineryStation,
    RestStop,
    Star,
}

impl ContainerType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "JumpPoint" => Some(ContainerType::JumpPoint),
            "Lagrange" => Some(ContainerType::Lagrange),
            "Moon" => Some(ContainerType::Moon),
            "NavalStation" => Some(ContainerType::NavalStation),
            "Planet" => Some(ContainerType::Planet),
            "RefineryStation" => Some(ContainerType::RefineryStation),
            "RestStop" => Some(ContainerType::RestStop),
            "Star" => Some(ContainerType::Star),
            _ => None,
        }
    }
}

/// Point of interest classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PoiType {
    AnimalArea,
    AsteroidBelt,
    Cave,
    ColonialBunker,
    ColonialOutpost,
    CommArray,
    DerelictOutpost,
    DerelictSettlement,
    DistributionCenter,
    Druglab,
    Easteregg,
    Event,
    ForwardOperatingBase,
    JumpPoint,
    LandingZone,
    Missing,
    MissionArea,
    ObjectContainer,
    OrbitalStation,
    Outpost,
    Picoball,
    Prison,
    Racetrack,
    RacetrackCommunity,
    River,
    Scrapyard,
    Spaceport,
    StashHouse,
    UndergroundFacility,
    Unknown,
    Wreck,
}

impl PoiType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "AnimalArea" => Some(PoiType::AnimalArea),
            "AsteroidBelt" => Some(PoiType::AsteroidBelt),
            "Cave" => Some(PoiType::Cave),
            "ColonialBunker" => Some(PoiType::ColonialBunker),
            "ColonialOutpost" => Some(PoiType::ColonialOutpost),
            "CommArray" => Some(PoiType::CommArray),
            "DerelictOutpost" => Some(PoiType::DerelictOutpost),
            "DerelictSettlement" => Some(PoiType::DerelictSettlement),
            "DistributionCenter" => Some(PoiType::DistributionCenter),
            "Druglab" => Some(PoiType::Druglab),
            "Easteregg" => Some(PoiType::Easteregg),
            "Event" => Some(PoiType::Event),
            "ForwardOperatingBase" => Some(PoiType::ForwardOperatingBase),
            "JumpPoint" => Some(PoiType::JumpPoint),
            "LandingZone" => Some(PoiType::LandingZone),
            "missing" => Some(PoiType::Missing),
            "MissionArea" => Some(PoiType::MissionArea),
            "ObjectContainer" => Some(PoiType::ObjectContainer),
            "OrbitalStation" => Some(PoiType::OrbitalStation),
            "Outpost" => Some(PoiType::Outpost),
            "Picoball" => Some(PoiType::Picoball),
            "Prison" => Some(PoiType::Prison),
            "Racetrack" => Some(PoiType::Racetrack),
            "RacetrackCommunity" => Some(PoiType::RacetrackCommunity),
            "River" => Some(PoiType::River),
            "Scrapyard" => Some(PoiType::Scrapyard),
            "Spaceport" => Some(PoiType::Spaceport),
            "StashHouse" => Some(PoiType::StashHouse),
            "UndergroundFacility" => Some(PoiType::UndergroundFacility),
            "Unknown" => Some(PoiType::Unknown),
            "Wreck" => Some(PoiType::Wreck),
            _ => None,
        }
    }
}

/// Celestial body or station container
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectContainer {
    pub id: u32,
    pub system: System,
    pub container_type: ContainerType,
    pub name: String,
    pub internal_name: String,
    pub position: Vector3,
    pub rot_vel: Vector3,
    pub rot_adj: Vector3,
    pub rot_quat: Quaternion,
    pub body_radius: f64,
    pub om_radius: f64,
    pub grid_radius: f64,
}

impl ObjectContainer {
    pub fn new(
        id: u32,
        system: System,
        container_type: ContainerType,
        name: String,
        internal_name: String,
        position: Vector3,
        rot_vel: Vector3,
        rot_adj: Vector3,
        rot_quat: Quaternion,
        body_radius: f64,
        om_radius: f64,
        grid_radius: f64,
    ) -> Self {
        Self {
            id,
            system,
            container_type,
            name,
            internal_name,
            position,
            rot_vel,
            rot_adj,
            rot_quat,
            body_radius,
            om_radius,
            grid_radius,
        }
    }
}

/// Point of interest location
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PointOfInterest {
    pub id: u32,
    pub name: String,
    pub system: System,
    pub obj_container: Option<String>,
    pub poi_type: PoiType,
    pub class: String,
    pub position: Vector3,
    pub has_qt_marker: bool,
    pub date_added: Option<String>,
    pub comment: Option<String>,
    pub with_version: Option<String>,
}

impl PointOfInterest {
    pub fn new(
        id: u32,
        name: String,
        system: System,
        obj_container: Option<String>,
        poi_type: PoiType,
        class: String,
        position: Vector3,
        has_qt_marker: bool,
        date_added: Option<String>,
        comment: Option<String>,
        with_version: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            system,
            obj_container,
            poi_type,
            class,
            position,
            has_qt_marker,
            date_added,
            comment,
            with_version,
        }
    }
}

/// Path complexity classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathComplexity {
    Direct,
    Simple,
    Complex,
}

impl fmt::Display for PathComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathComplexity::Direct => write!(f, "DIRECT"),
            PathComplexity::Simple => write!(f, "SIMPLE"),
            PathComplexity::Complex => write!(f, "COMPLEX"),
        }
    }
}

/// Travel method classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TravelType {
    Quantum,
    Sublight,
}

impl fmt::Display for TravelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TravelType::Quantum => write!(f, "QUANTUM TRAVEL"),
            TravelType::Sublight => write!(f, "SUBLIGHT"),
        }
    }
}

/// Entity types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    PointOfInterest,
    ObjectContainer,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntityType::PointOfInterest => write!(f, "poi"),
            EntityType::ObjectContainer => write!(f, "container"),
        }
    }
}

impl EntityType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "poi" => Some(EntityType::PointOfInterest),
            "container" => Some(EntityType::ObjectContainer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Entity {
    PointOfInterest(PointOfInterest),
    ObjectContainer(ObjectContainer),
}


/// Navigation node types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NavNodeType {
    Origin,
    Destination,
    OrbitalMarker,
    QuantumMarker,
    Intermediate,
}

impl fmt::Display for NavNodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NavNodeType::Origin => write!(f, "origin"),
            NavNodeType::Destination => write!(f, "destination"),
            NavNodeType::OrbitalMarker => write!(f, "om"),
            NavNodeType::QuantumMarker => write!(f, "qt_marker"),
            NavNodeType::Intermediate => write!(f, "intermediate"),
        }
    }
}

/// Navigation search direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchDirection {
    Forward,
    Backward,
    Both,
}

/// Enhanced navigation node for bidirectional pathfinding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavNode {
    pub position: Vector3,
    pub parent_node: Option<Arc<NavNode>>,
    pub g_cost: f64,             // Cost from start to this node
    pub h_cost: f64,             // Estimated cost from this node to goal
    pub f_cost: f64,             // Total cost (g + h)
    pub node_type: NavNodeType,
    pub name: String,
    pub container_ref: Option<Arc<ObjectContainer>>,
    pub obstruction_path: bool,  // Flag for obstruction avoidance
    pub search_direction: SearchDirection,
}

impl NavNode {
    pub fn new(
        position: Vector3,
        node_type: NavNodeType,
        name: String,
        container_ref: Option<Arc<ObjectContainer>>,
    ) -> Self {
        Self {
            position,
            parent_node: None,
            g_cost: 0.0,
            h_cost: 0.0,
            f_cost: 0.0,
            node_type,
            name,
            container_ref,
            obstruction_path: false,
            search_direction: SearchDirection::Forward,
        }
    }
    
    pub fn calculate_f_cost(&mut self) {
        self.f_cost = self.g_cost + self.h_cost;
    }
    
    pub fn equals(&self, other: &NavNode) -> bool {
        // Consider nodes equal if they have the same position
        (self.position.x - other.position.x).abs() < 1e-6 &&
        (self.position.y - other.position.y).abs() < 1e-6 &&
        (self.position.z - other.position.z).abs() < 1e-6
    }
}

/// Path segment for navigation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSegment {
    pub from: PathPoint,
    pub to: PathPoint,
    pub distance: f64,
    pub travel_type: TravelType,
    pub estimated_time: f64,
    pub direction: EulerAngles,
    pub obstruction: Option<String>,
    pub is_obstruction_bypass: bool,
}

/// Point in a navigation path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPoint {
    pub name: String,
    pub position: Vector3,
    pub point_type: NavNodeType,
}

/// Navigation plan with obstruction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationPlan {
    pub segments: Vec<PathSegment>,
    pub total_distance: f64,
    pub total_estimated_time: f64,
    pub quantum_jumps: u32,
    pub obstruction_detected: bool,
    pub obstructions: Vec<String>,
    pub path_complexity: PathComplexity,
    pub origin_container: Option<Arc<ObjectContainer>>,
}

/// Navigation result data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationResult {
    pub distance: f64,
    pub direction: EulerAngles,
    pub eta: f64,
    pub angular_deviation: Option<f64>,
    pub closest_orbital_marker: Option<NamedDistance>,
    pub closest_qt_beacon: Option<NamedDistance>,
}

/// Named distance structure for references
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedDistance {
    pub name: String,
    pub distance: f64,
}

/// Line of sight check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineOfSightResult {
    pub has_los: bool,
    pub obstruction: Option<Arc<ObjectContainer>>,
}

/// Meeting point for bidirectional search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeetingPoint {
    pub forward_node: Arc<NavNode>,
    pub backward_node: Arc<NavNode>,
    pub total_cost: f64,
}

/// Visibility edge for path planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityEdge {
    pub from_node: Arc<NavNode>,
    pub to_node: Arc<NavNode>,
    pub distance: f64,
    pub has_los: bool,
    pub obstruction: Option<Arc<ObjectContainer>>,
}

/// Data provider trait for astronomical database access
pub trait AstronomicalDataProvider {
    fn get_points_of_interest(&self) -> &[PointOfInterest];
    fn get_object_containers(&self) -> &[ObjectContainer];
    fn get_point_of_interest_by_name(&self, name: &str) -> Option<&PointOfInterest>;
    fn get_object_container_by_name(&self, name: &str) -> Option<&ObjectContainer>;
}

/// Default implementation of astronomical data provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAstronomicalData {
    pub pois: Vec<PointOfInterest>,
    pub containers: Vec<ObjectContainer>,
    pub poi_name_map: HashMap<String, usize>,
    pub container_name_map: HashMap<String, usize>,
}

impl StaticAstronomicalData {
    pub fn new(pois: Vec<PointOfInterest>, containers: Vec<ObjectContainer>) -> Self {
        let mut poi_name_map = HashMap::new();
        let mut container_name_map = HashMap::new();
        
        for (i, poi) in pois.iter().enumerate() {
            poi_name_map.insert(poi.name.clone(), i);
        }
        
        for (i, container) in containers.iter().enumerate() {
            container_name_map.insert(container.name.clone(), i);
        }
        
        Self {
            pois,
            containers,
            poi_name_map,
            container_name_map,
        }
    }
}

impl AstronomicalDataProvider for StaticAstronomicalData {
    fn get_points_of_interest(&self) -> &[PointOfInterest] {
        &self.pois
    }
    
    fn get_object_containers(&self) -> &[ObjectContainer] {
        &self.containers
    }
    
    fn get_point_of_interest_by_name(&self, name: &str) -> Option<&PointOfInterest> {
        self.poi_name_map.get(name).map(|&i| &self.pois[i])
    }
    
    fn get_object_container_by_name(&self, name: &str) -> Option<&ObjectContainer> {
        self.container_name_map.get(name).map(|&i| &self.containers[i])
    }
}

#[cfg(test)]
mod vector3_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_vector3_creation() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        assert_eq!(v.x, 1.0);
        assert_eq!(v.y, 2.0);
        assert_eq!(v.z, 3.0);
    }

    #[test]
    fn test_vector3_distance() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        assert_relative_eq!(v1.distance(&v2), 5.196152422706632);
        
        // Distance to self should be zero
        assert_eq!(v1.distance(&v1), 0.0);
    }

    #[test]
    fn test_vector3_normalized() {
        let v = Vector3::new(3.0, 4.0, 0.0);
        let normalized = v.normalized();
        assert_relative_eq!(normalized.x, 0.6);
        assert_relative_eq!(normalized.y, 0.8);
        assert_relative_eq!(normalized.z, 0.0);
        
        // Length of normalized vector should be 1
        let length = (normalized.x.powi(2) + normalized.y.powi(2) + normalized.z.powi(2)).sqrt();
        assert_relative_eq!(length, 1.0);
        
        // Test zero vector
        let zero_vec = Vector3::new(0.0, 0.0, 0.0);
        let normalized_zero = zero_vec.normalized();
        assert_eq!(normalized_zero, zero_vec);
        
        // Test very small vector
        let tiny_vec = Vector3::new(1e-10, 1e-10, 1e-10);
        let normalized_tiny = tiny_vec.normalized();
        assert_eq!(normalized_tiny, tiny_vec);
    }
}

#[cfg(test)]
mod quaternion_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_quaternion_creation() {
        let q = Quaternion::new(1.0, 2.0, 3.0, 4.0);
        assert_eq!(q.w, 1.0);
        assert_eq!(q.x, 2.0);
        assert_eq!(q.y, 3.0);
        assert_eq!(q.z, 4.0);
    }

    #[test]
    fn test_quaternion_identity() {
        let q = Quaternion::identity();
        assert_eq!(q.w, 1.0);
        assert_eq!(q.x, 0.0);
        assert_eq!(q.y, 0.0);
        assert_eq!(q.z, 0.0);
    }

    #[test]
    fn test_quaternion_conjugate() {
        let q = Quaternion::new(1.0, 2.0, 3.0, 4.0);
        let conj = q.conjugate();
        assert_eq!(conj.w, 1.0);
        assert_eq!(conj.x, -2.0);
        assert_eq!(conj.y, -3.0);
        assert_eq!(conj.z, -4.0);
    }

    #[test]
    fn test_quaternion_normalize() {
        let q = Quaternion::new(2.0, 2.0, 2.0, 2.0);
        let normalized = q.normalize();
        let expected = 0.5; // 2.0 / sqrt(16)
        assert_relative_eq!(normalized.w, expected);
        assert_relative_eq!(normalized.x, expected);
        assert_relative_eq!(normalized.y, expected);
        assert_relative_eq!(normalized.z, expected);
    }

    #[test]
    fn test_quaternion_multiplication() {
        let q1 = Quaternion::new(1.0, 2.0, 3.0, 4.0);
        let q2 = Quaternion::new(5.0, 6.0, 7.0, 8.0);
        let result = q1.multiply(&q2);
        
        // Expected: (1*5 - 2*6 - 3*7 - 4*8, 1*6 + 2*5 + 3*8 - 4*7, 1*7 - 2*8 + 3*5 + 4*6, 1*8 + 2*7 - 3*6 + 4*5)
        assert_eq!(result.w, -60.0);
        assert_eq!(result.x, 12.0);
        assert_eq!(result.y, 30.0);
        assert_eq!(result.z, 24.0);
    }

    #[test]
    fn test_rotate_vector() {
        // 90-degree rotation around Y
        let q = Quaternion::from_euler(0.0, 90.0, 0.0);
        let v = Vector3::new(1.0, 0.0, 0.0);
        let rotated = q.rotate_vector(&v);
        
        assert_relative_eq!(rotated.x, 0.0, epsilon = 1e-10);
        assert_relative_eq!(rotated.y, 0.0, epsilon = 1e-10);
        assert_relative_eq!(rotated.z, -1.0, epsilon = 1e-10);
    }

    #[test]
    fn test_euler_conversion() {
        // Test conversion from Euler to quaternion and back
        let original_angles = (30.0, 45.0, 60.0); // pitch, yaw, roll
        let q = Quaternion::from_euler(original_angles.0, original_angles.1, original_angles.2);
        let result_angles = q.to_euler();
        
        assert_relative_eq!(result_angles.0, original_angles.0, epsilon = 1e-5);
        assert_relative_eq!(result_angles.1, original_angles.1, epsilon = 1e-5);
        assert_relative_eq!(result_angles.2, original_angles.2, epsilon = 1e-5);
        
        // Test gimbal lock case
        let gimbal_lock = Quaternion::from_euler(90.0, 0.0, 0.0);
        let angles = gimbal_lock.to_euler();
        assert_relative_eq!(angles.0, 90.0, epsilon = 1e-5);
    }
}

#[cfg(test)]
mod system_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_system_from_str() {
        assert_eq!(System::from_str("Stanton"), Some(System::Stanton));
        assert_eq!(System::from_str("Pyro"), Some(System::Pyro));
        assert_eq!(System::from_str("Nyx"), Some(System::Nyx));
        assert_eq!(System::from_str("Ellis"), Some(System::Ellis));
        assert_eq!(System::from_str("Sol"), Some(System::Sol));
        assert_eq!(System::from_str("Unknown"), None);
    }

    #[test]
    fn test_system_display() {
        assert_eq!(format!("{}", System::Stanton), "Stanton");
        assert_eq!(format!("{}", System::Pyro), "Pyro");
        assert_eq!(format!("{}", System::Nyx), "Nyx");
        assert_eq!(format!("{}", System::Ellis), "Ellis");
        assert_eq!(format!("{}", System::Sol), "Sol");
    }
}

#[cfg(test)]
mod container_type_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_container_type_from_str() {
        assert_eq!(ContainerType::from_str("JumpPoint"), Some(ContainerType::JumpPoint));
        assert_eq!(ContainerType::from_str("Lagrange"), Some(ContainerType::Lagrange));
        assert_eq!(ContainerType::from_str("Moon"), Some(ContainerType::Moon));
        assert_eq!(ContainerType::from_str("NavalStation"), Some(ContainerType::NavalStation));
        assert_eq!(ContainerType::from_str("Planet"), Some(ContainerType::Planet));
        assert_eq!(ContainerType::from_str("RefineryStation"), Some(ContainerType::RefineryStation));
        assert_eq!(ContainerType::from_str("RestStop"), Some(ContainerType::RestStop));
        assert_eq!(ContainerType::from_str("Star"), Some(ContainerType::Star));
        assert_eq!(ContainerType::from_str("Unknown"), None);
    }
}

#[cfg(test)]
mod poi_type_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_poi_type_from_str() {
        assert_eq!(PoiType::from_str("AnimalArea"), Some(PoiType::AnimalArea));
        assert_eq!(PoiType::from_str("AsteroidBelt"), Some(PoiType::AsteroidBelt));
        assert_eq!(PoiType::from_str("Cave"), Some(PoiType::Cave));
        assert_eq!(PoiType::from_str("Outpost"), Some(PoiType::Outpost));
        assert_eq!(PoiType::from_str("missing"), Some(PoiType::Missing));
        assert_eq!(PoiType::from_str("Unknown"), Some(PoiType::Unknown));
        assert_eq!(PoiType::from_str("NotAPoi"), None);
    }
}

#[cfg(test)]
mod object_container_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_object_container_creation() {
        let container = ObjectContainer::new(
            1,
            System::Stanton,
            ContainerType::Planet,
            "Microtech".to_string(),
            "microtech_planet".to_string(),
            Vector3::new(1.0, 2.0, 3.0),
            Vector3::new(0.0, 0.0, 0.001),
            Vector3::new(0.0, 0.0, 0.0),
            Quaternion::identity(),
            500.0,
            700.0,
            1000.0,
        );
        
        assert_eq!(container.id, 1);
        assert_eq!(container.system, System::Stanton);
        assert_eq!(container.container_type, ContainerType::Planet);
        assert_eq!(container.name, "Microtech");
        assert_eq!(container.internal_name, "microtech_planet");
        assert_eq!(container.position, Vector3::new(1.0, 2.0, 3.0));
        assert_eq!(container.rot_vel, Vector3::new(0.0, 0.0, 0.001));
        assert_eq!(container.rot_adj, Vector3::new(0.0, 0.0, 0.0));
        assert_eq!(container.rot_quat, Quaternion::identity());
        assert_eq!(container.body_radius, 500.0);
        assert_eq!(container.om_radius, 700.0);
        assert_eq!(container.grid_radius, 1000.0);
    }
}

#[cfg(test)]
mod point_of_interest_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_point_of_interest_creation() {
        let poi = PointOfInterest::new(
            1,
            "New Babbage".to_string(),
            System::Stanton,
            Some("Microtech".to_string()),
            PoiType::Spaceport,
            "city".to_string(),
            Vector3::new(1.0, 2.0, 3.0),
            true,
            Some("2023-01-01".to_string()),
            Some("Test comment".to_string()),
            Some("3.18".to_string()),
        );
        
        assert_eq!(poi.id, 1);
        assert_eq!(poi.name, "New Babbage");
        assert_eq!(poi.system, System::Stanton);
        assert_eq!(poi.obj_container, Some("Microtech".to_string()));
        assert_eq!(poi.poi_type, PoiType::Spaceport);
        assert_eq!(poi.class, "city");
        assert_eq!(poi.position, Vector3::new(1.0, 2.0, 3.0));
        assert_eq!(poi.has_qt_marker, true);
        assert_eq!(poi.date_added, Some("2023-01-01".to_string()));
        assert_eq!(poi.comment, Some("Test comment".to_string()));
        assert_eq!(poi.with_version, Some("3.18".to_string()));
    }
}

#[cfg(test)]
mod enum_display_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_path_complexity_display() {
        assert_eq!(format!("{}", PathComplexity::Direct), "DIRECT");
        assert_eq!(format!("{}", PathComplexity::Simple), "SIMPLE");
        assert_eq!(format!("{}", PathComplexity::Complex), "COMPLEX");
    }

    #[test]
    fn test_travel_type_display() {
        assert_eq!(format!("{}", TravelType::Quantum), "QUANTUM TRAVEL");
        assert_eq!(format!("{}", TravelType::Sublight), "SUBLIGHT");
    }

    #[test]
    fn test_entity_type_display() {
        assert_eq!(format!("{}", EntityType::PointOfInterest), "poi");
        assert_eq!(format!("{}", EntityType::ObjectContainer), "container");
    }

    #[test]
    fn test_entity_type_from_str() {
        assert_eq!(EntityType::from_str("poi"), Some(EntityType::PointOfInterest));
        assert_eq!(EntityType::from_str("container"), Some(EntityType::ObjectContainer));
        assert_eq!(EntityType::from_str("unknown"), None);
    }

    #[test]
    fn test_nav_node_type_display() {
        assert_eq!(format!("{}", NavNodeType::Origin), "origin");
        assert_eq!(format!("{}", NavNodeType::Destination), "destination");
        assert_eq!(format!("{}", NavNodeType::OrbitalMarker), "om");
        assert_eq!(format!("{}", NavNodeType::QuantumMarker), "qt_marker");
        assert_eq!(format!("{}", NavNodeType::Intermediate), "intermediate");
    }
}

#[cfg(test)]
mod nav_node_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_nav_node_creation() {
        let container = Arc::new(ObjectContainer::new(
            1,
            System::Stanton,
            ContainerType::Planet,
            "Microtech".to_string(),
            "microtech_planet".to_string(),
            Vector3::new(1.0, 2.0, 3.0),
            Vector3::new(0.0, 0.0, 0.001),
            Vector3::new(0.0, 0.0, 0.0),
            Quaternion::identity(),
            500.0,
            700.0,
            1000.0,
        ));
        
        let node = NavNode::new(
            Vector3::new(4.0, 5.0, 6.0),
            NavNodeType::OrbitalMarker,
            "OM-1".to_string(),
            Some(container.clone()),
        );
        
        assert_eq!(node.position, Vector3::new(4.0, 5.0, 6.0));
        assert_eq!(node.node_type, NavNodeType::OrbitalMarker);
        assert_eq!(node.name, "OM-1");
        assert!(node.container_ref.is_some());
        assert_eq!(node.g_cost, 0.0);
        assert_eq!(node.h_cost, 0.0);
        assert_eq!(node.f_cost, 0.0);
        assert_eq!(node.obstruction_path, false);
        assert_eq!(node.search_direction, SearchDirection::Forward);
    }

    #[test]
    fn test_calculate_f_cost() {
        let mut node = NavNode::new(
            Vector3::new(1.0, 2.0, 3.0),
            NavNodeType::Origin,
            "Origin".to_string(),
            None,
        );
        
        node.g_cost = 10.0;
        node.h_cost = 20.0;
        node.calculate_f_cost();
        
        assert_eq!(node.f_cost, 30.0);
    }

    #[test]
    fn test_node_equals() {
        let node1 = NavNode::new(
            Vector3::new(1.0, 2.0, 3.0),
            NavNodeType::Origin,
            "Origin".to_string(),
            None,
        );
        
        let node2 = NavNode::new(
            Vector3::new(1.0, 2.0, 3.0),
            NavNodeType::Destination,  // Different type but same position
            "Destination".to_string(), // Different name but same position
            None,
        );
        
        let node3 = NavNode::new(
            Vector3::new(4.0, 5.0, 6.0), // Different position
            NavNodeType::Origin,
            "Origin".to_string(),
            None,
        );
        
        assert!(node1.equals(&node2)); // Should be equal (same position)
        assert!(!node1.equals(&node3)); // Should not be equal (different position)
    }
}

#[cfg(test)]
mod astronomical_data_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_static_astronomical_data() {
        let pois = vec![
            PointOfInterest::new(
                1,
                "New Babbage".to_string(),
                System::Stanton,
                Some("Microtech".to_string()),
                PoiType::Spaceport,
                "city".to_string(),
                Vector3::new(1.0, 2.0, 3.0),
                true,
                None,
                None,
                None,
            ),
            PointOfInterest::new(
                2,
                "Port Olisar".to_string(),
                System::Stanton,
                Some("Crusader".to_string()),
                PoiType::OrbitalStation,
                "station".to_string(),
                Vector3::new(4.0, 5.0, 6.0),
                true,
                None,
                None,
                None,
            ),
        ];
        
        let containers = vec![
            ObjectContainer::new(
                1,
                System::Stanton,
                ContainerType::Planet,
                "Microtech".to_string(),
                "microtech_planet".to_string(),
                Vector3::new(10.0, 20.0, 30.0),
                Vector3::new(0.0, 0.0, 0.001),
                Vector3::new(0.0, 0.0, 0.0),
                Quaternion::identity(),
                500.0,
                700.0,
                1000.0,
            ),
            ObjectContainer::new(
                2,
                System::Stanton,
                ContainerType::Planet,
                "Crusader".to_string(),
                "crusader_planet".to_string(),
                Vector3::new(40.0, 50.0, 60.0),
                Vector3::new(0.0, 0.0, 0.001),
                Vector3::new(0.0, 0.0, 0.0),
                Quaternion::identity(),
                600.0,
                800.0,
                1100.0,
            ),
        ];
        
        let data = StaticAstronomicalData::new(pois.clone(), containers.clone());
        
        // Test that data was stored correctly
        assert_eq!(data.get_points_of_interest().len(), 2);
        assert_eq!(data.get_object_containers().len(), 2);
        
        // Test lookup by name
        let found_poi = data.get_point_of_interest_by_name("New Babbage");
        assert!(found_poi.is_some());
        assert_eq!(found_poi.unwrap(), &pois[0]);
        
        let found_container = data.get_object_container_by_name("Crusader");
        assert!(found_container.is_some());
        assert_eq!(found_container.unwrap(), &containers[1]);
        
        // Test lookup with non-existent name
        let not_found_poi = data.get_point_of_interest_by_name("Non-existent POI");
        assert!(not_found_poi.is_none());
        
        let not_found_container = data.get_object_container_by_name("Non-existent Container");
        assert!(not_found_container.is_none());
    }
}

#[cfg(test)]
mod euler_angles_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_euler_angles_creation() {
        let angles = EulerAngles::new(30.0, 45.0, 60.0);
        assert_eq!(angles.pitch, 30.0);
        assert_eq!(angles.yaw, 45.0);
        assert_eq!(angles.roll, 60.0);
    }
}

#[cfg(test)]
mod entity_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_entity_enum() {
        let poi = PointOfInterest::new(
            1,
            "Test POI".to_string(),
            System::Stanton,
            None,
            PoiType::Outpost,
            "outpost".to_string(),
            Vector3::new(1.0, 2.0, 3.0),
            true,
            None,
            None,
            None,
        );
        
        let container = ObjectContainer::new(
            1,
            System::Stanton,
            ContainerType::Planet,
            "Test Planet".to_string(),
            "test_planet".to_string(),
            Vector3::new(10.0, 20.0, 30.0),
            Vector3::new(0.0, 0.0, 0.001),
            Vector3::new(0.0, 0.0, 0.0),
            Quaternion::identity(),
            500.0,
            700.0,
            1000.0,
        );
        
        let entity_poi = Entity::PointOfInterest(poi.clone());
        let entity_container = Entity::ObjectContainer(container.clone());
        
        match entity_poi {
            Entity::PointOfInterest(p) => assert_eq!(p, poi),
            _ => panic!("Expected PointOfInterest"),
        }
        
        match entity_container {
            Entity::ObjectContainer(c) => assert_eq!(c, container),
            _ => panic!("Expected ObjectContainer"),
        }
    }
}

#[cfg(test)]
mod path_segment_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_path_segment_creation() {
        let from_point = PathPoint {
            name: "Origin".to_string(),
            position: Vector3::new(0.0, 0.0, 0.0),
            point_type: NavNodeType::Origin,
        };
        
        let to_point = PathPoint {
            name: "Destination".to_string(),
            position: Vector3::new(100.0, 0.0, 0.0),
            point_type: NavNodeType::Destination,
        };
        
        let segment = PathSegment {
            from: from_point,
            to: to_point,
            distance: 100.0,
            travel_type: TravelType::Quantum,
            estimated_time: 10.0,
            direction: EulerAngles::new(0.0, 0.0, 0.0),
            obstruction: None,
            is_obstruction_bypass: false,
        };
        
        assert_eq!(segment.distance, 100.0);
        assert_eq!(segment.travel_type, TravelType::Quantum);
        assert_eq!(segment.estimated_time, 10.0);
        assert_eq!(segment.is_obstruction_bypass, false);
    }
}

#[cfg(test)]
mod navigation_plan_tests {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_navigation_plan_creation() {
        let segments = vec![
            PathSegment {
                from: PathPoint {
                    name: "Origin".to_string(),
                    position: Vector3::new(0.0, 0.0, 0.0),
                    point_type: NavNodeType::Origin,
                },
                to: PathPoint {
                    name: "Midpoint".to_string(),
                    position: Vector3::new(50.0, 0.0, 0.0),
                    point_type: NavNodeType::Intermediate,
                },
                distance: 50.0,
                travel_type: TravelType::Quantum,
                estimated_time: 5.0,
                direction: EulerAngles::new(0.0, 0.0, 0.0),
                obstruction: None,
                is_obstruction_bypass: false,
            },
            PathSegment {
                from: PathPoint {
                    name: "Midpoint".to_string(),
                    position: Vector3::new(50.0, 0.0, 0.0),
                    point_type: NavNodeType::Intermediate,
                },
                to: PathPoint {
                    name: "Destination".to_string(),
                    position: Vector3::new(100.0, 0.0, 0.0),
                    point_type: NavNodeType::Destination,
                },
                distance: 50.0,
                travel_type: TravelType::Quantum,
                estimated_time: 5.0,
                direction: EulerAngles::new(0.0, 0.0, 0.0),
                obstruction: None,
                is_obstruction_bypass: false,
            },
        ];
        
        let container = Arc::new(ObjectContainer::new(
            1,
            System::Stanton,
            ContainerType::Planet,
            "Origin Planet".to_string(),
            "origin_planet".to_string(),
            Vector3::new(0.0, 0.0, 0.0),
            Vector3::new(0.0, 0.0, 0.0),
            Vector3::new(0.0, 0.0, 0.0),
            Quaternion::identity(),
            100.0,
            200.0,
            300.0,
        ));
        
        let plan = NavigationPlan {
            segments,
            total_distance: 100.0,
            total_estimated_time: 10.0,
            quantum_jumps: 2,
            obstruction_detected: false,
            obstructions: vec![],
            path_complexity: PathComplexity::Simple,
            origin_container: Some(container.clone()),
        };
        
        assert_eq!(plan.segments.len(), 2);
        assert_eq!(plan.total_distance, 100.0);
        assert_eq!(plan.total_estimated_time, 10.0);
        assert_eq!(plan.quantum_jumps, 2);
        assert_eq!(plan.obstruction_detected, false);
        assert_eq!(plan.obstructions.len(), 0);
        assert_eq!(plan.path_complexity, PathComplexity::Simple);
        assert!(plan.origin_container.is_some());
    }
}

#[cfg(test)]
mod navigation_result_tests {
    use super::*;

    #[test]
    fn test_navigation_result_creation() {
        let result = NavigationResult {
            distance: 1000.0,
            direction: EulerAngles::new(10.0, 20.0, 30.0),
            eta: 120.0,
            angular_deviation: Some(5.0),
            closest_orbital_marker: Some(NamedDistance {
                name: "OM-1".to_string(),
                distance: 500.0,
            }),
            closest_qt_beacon: Some(NamedDistance {
                name: "Port Olisar".to_string(),
                distance: 750.0,
            }),
        };
        
        assert_eq!(result.distance, 1000.0);
        assert_eq!(result.direction.pitch, 10.0);
        assert_eq!(result.direction.yaw, 20.0);
        assert_eq!(result.direction.roll, 30.0);
        assert_eq!(result.eta, 120.0);
        assert_eq!(result.angular_deviation, Some(5.0));
        
        assert!(result.closest_orbital_marker.is_some());
        let om = result.closest_orbital_marker.unwrap();
        assert_eq!(om.name, "OM-1");
        assert_eq!(om.distance, 500.0);
        
        assert!(result.closest_qt_beacon.is_some());
        let beacon = result.closest_qt_beacon.unwrap();
        assert_eq!(beacon.name, "Port Olisar");
        assert_eq!(beacon.distance, 750.0);
    }
}

#[cfg(test)]
mod named_distance_tests {
    use super::*;

    #[test]
    fn test_named_distance_creation() {
        let named_dist = NamedDistance {
            name: "Test Location".to_string(),
            distance: 123.45,
        };
        
        assert_eq!(named_dist.name, "Test Location");
        assert_eq!(named_dist.distance, 123.45);
    }
}

#[cfg(test)]
mod line_of_sight_tests {
    use super::*;

    #[test]
    fn test_line_of_sight_result() {
        // Test with no obstruction
        let los_clear = LineOfSightResult {
            has_los: true,
            obstruction: None,
        };
        
        assert_eq!(los_clear.has_los, true);
        assert!(los_clear.obstruction.is_none());
        
        // Test with obstruction
        let container = Arc::new(ObjectContainer::new(
            1,
            System::Stanton,
            ContainerType::Planet,
            "Hurston".to_string(),
            "hurston_planet".to_string(),
            Vector3::new(0.0, 0.0, 0.0),
            Vector3::new(0.0, 0.0, 0.0),
            Vector3::new(0.0, 0.0, 0.0),
            Quaternion::identity(),
            1000.0,
            1200.0,
            1500.0,
        ));
        
        let los_blocked = LineOfSightResult {
            has_los: false,
            obstruction: Some(container.clone()),
        };
        
        assert_eq!(los_blocked.has_los, false);
        assert!(los_blocked.obstruction.is_some());
        assert_eq!(los_blocked.obstruction.as_ref().unwrap().name, "Hurston");
    }
}

#[cfg(test)]
mod meeting_point_tests {
    use super::*;

    #[test]
    fn test_meeting_point_creation() {
        let forward_node = Arc::new(NavNode::new(
            Vector3::new(10.0, 0.0, 0.0),
            NavNodeType::Intermediate,
            "Forward Node".to_string(),
            None,
        ));
        
        let backward_node = Arc::new(NavNode::new(
            Vector3::new(20.0, 0.0, 0.0),
            NavNodeType::Intermediate,
            "Backward Node".to_string(),
            None,
        ));
        
        let meeting_point = MeetingPoint {
            forward_node: forward_node.clone(),
            backward_node: backward_node.clone(),
            total_cost: 50.0,
        };
        
        assert_eq!(meeting_point.forward_node.name, "Forward Node");
        assert_eq!(meeting_point.backward_node.name, "Backward Node");
        assert_eq!(meeting_point.total_cost, 50.0);
    }
}

#[cfg(test)]
mod visibility_edge_tests {
    use super::*;

    #[test]
    fn test_visibility_edge_creation() {
        let from_node = Arc::new(NavNode::new(
            Vector3::new(0.0, 0.0, 0.0),
            NavNodeType::Origin,
            "Origin".to_string(),
            None,
        ));
        
        let to_node = Arc::new(NavNode::new(
            Vector3::new(100.0, 0.0, 0.0),
            NavNodeType::Destination,
            "Destination".to_string(),
            None,
        ));
        
        // Edge with clear line of sight
        let clear_edge = VisibilityEdge {
            from_node: from_node.clone(),
            to_node: to_node.clone(),
            distance: 100.0,
            has_los: true,
            obstruction: None,
        };
        
        assert_eq!(clear_edge.from_node.name, "Origin");
        assert_eq!(clear_edge.to_node.name, "Destination");
        assert_eq!(clear_edge.distance, 100.0);
        assert_eq!(clear_edge.has_los, true);
        assert!(clear_edge.obstruction.is_none());
        
        // Edge with obstruction
        let container = Arc::new(ObjectContainer::new(
            1,
            System::Stanton,
            ContainerType::Planet,
            "Blocking Planet".to_string(),
            "blocking_planet".to_string(),
            Vector3::new(50.0, 0.0, 0.0),
            Vector3::new(0.0, 0.0, 0.0),
            Vector3::new(0.0, 0.0, 0.0),
            Quaternion::identity(),
            25.0,
            50.0,
            100.0,
        ));
        
        let blocked_edge = VisibilityEdge {
            from_node: from_node.clone(),
            to_node: to_node.clone(),
            distance: 100.0,
            has_los: false,
            obstruction: Some(container.clone()),
        };
        
        assert_eq!(blocked_edge.has_los, false);
        assert!(blocked_edge.obstruction.is_some());
        assert_eq!(blocked_edge.obstruction.as_ref().unwrap().name, "Blocking Planet");
    }
}

#[cfg(test)]
mod path_point_tests {
    use super::*;

    #[test]
    fn test_path_point_creation() {
        let point = PathPoint {
            name: "Checkpoint Alpha".to_string(),
            position: Vector3::new(123.0, 456.0, 789.0),
            point_type: NavNodeType::Intermediate,
        };
        
        assert_eq!(point.name, "Checkpoint Alpha");
        assert_eq!(point.position, Vector3::new(123.0, 456.0, 789.0));
        assert_eq!(point.point_type, NavNodeType::Intermediate);
    }
}

#[cfg(test)]
mod entity_enum_additional_tests {
    use super::*;

    #[test]
    fn test_entity_enum_pattern_matching() {
        let poi = PointOfInterest::new(
            1,
            "Test POI".to_string(),
            System::Stanton,
            None,
            PoiType::Outpost,
            "outpost".to_string(),
            Vector3::new(1.0, 2.0, 3.0),
            true,
            None,
            None,
            None,
        );
        
        let entity = Entity::PointOfInterest(poi.clone());
        
        // Test pattern matching
        let position = match &entity {
            Entity::PointOfInterest(p) => p.position,
            Entity::ObjectContainer(c) => c.position,
        };
        
        assert_eq!(position, Vector3::new(1.0, 2.0, 3.0));
    }
}

#[cfg(test)]
mod search_direction_tests {
    use super::*;
    
    #[test]
    fn test_search_direction_variants() {
        // Ensure variants can be created and compared correctly
        let forward = SearchDirection::Forward;
        let backward = SearchDirection::Backward;
        let both = SearchDirection::Both;
        
        assert_ne!(forward, backward);
        assert_ne!(forward, both);
        assert_ne!(backward, both);
        
        // Test pattern matching
        match forward {
            SearchDirection::Forward => {}
            _ => panic!("Expected Forward"),
        }
        
        match backward {
            SearchDirection::Backward => {}
            _ => panic!("Expected Backward"),
        }
        
        match both {
            SearchDirection::Both => {}
            _ => panic!("Expected Both"),
        }
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use serde_json;
    
    #[test]
    fn test_vector3_serialization() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&v).unwrap();
        
        // Deserialize from JSON
        let deserialized: Vector3 = serde_json::from_str(&serialized).unwrap();
        
        // Check equality
        assert_eq!(v, deserialized);
    }
    
    #[test]
    fn test_quaternion_serialization() {
        let q = Quaternion::new(1.0, 2.0, 3.0, 4.0);
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&q).unwrap();
        
        // Deserialize from JSON
        let deserialized: Quaternion = serde_json::from_str(&serialized).unwrap();
        
        // Check equality
        assert_eq!(q, deserialized);
    }
    
    #[test]
    fn test_system_serialization() {
        let system = System::Stanton;
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&system).unwrap();
        
        // Deserialize from JSON
        let deserialized: System = serde_json::from_str(&serialized).unwrap();
        
        // Check equality
        assert_eq!(system, deserialized);
    }
    
    #[test]
    fn test_container_type_serialization() {
        let container_type = ContainerType::Planet;
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&container_type).unwrap();
        
        // Deserialize from JSON
        let deserialized: ContainerType = serde_json::from_str(&serialized).unwrap();
        
        // Check equality
        assert_eq!(container_type, deserialized);
    }
    
    #[test]
    fn test_poi_type_serialization() {
        let poi_type = PoiType::Outpost;
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&poi_type).unwrap();
        
        // Deserialize from JSON
        let deserialized: PoiType = serde_json::from_str(&serialized).unwrap();
        
        // Check equality
        assert_eq!(poi_type, deserialized);
    }
}

#[cfg(test)]
mod vector3_additional_operations {
    use super::*;
    use approx::assert_relative_eq;
    
    // These tests check behavior that's not explicitly implemented 
    // but would be useful to add to Vector3 in the future
    
    #[test]
    fn test_vector3_zero() {
        let zero = Vector3::new(0.0, 0.0, 0.0);
        assert_eq!(zero.x, 0.0);
        assert_eq!(zero.y, 0.0);
        assert_eq!(zero.z, 0.0);
    }
    
    #[test]
    fn test_vector3_magnitude() {
        let v = Vector3::new(3.0, 4.0, 0.0);
        let magnitude = (v.x.powi(2) + v.y.powi(2) + v.z.powi(2)).sqrt();
        assert_relative_eq!(magnitude, 5.0);
    }
    
    #[test]
    fn test_vector3_dot_product() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        
        // Manually calculate dot product
        let dot_product = v1.x * v2.x + v1.y * v2.y + v1.z * v2.z;
        assert_eq!(dot_product, 32.0);
    }
    
    #[test]
    fn test_vector3_cross_product() {
        let v1 = Vector3::new(1.0, 0.0, 0.0);
        let v2 = Vector3::new(0.0, 1.0, 0.0);
        
        // Manually calculate cross product
        let cross_product_x = v1.y * v2.z - v1.z * v2.y;
        let cross_product_y = v1.z * v2.x - v1.x * v2.z;
        let cross_product_z = v1.x * v2.y - v1.y * v2.x;
        
        let cross_product = Vector3::new(cross_product_x, cross_product_y, cross_product_z);
        
        assert_eq!(cross_product, Vector3::new(0.0, 0.0, 1.0));
    }
}

#[cfg(test)]
mod pathfinding_edge_cases {
    use super::*;
    
    #[test]
    fn test_nav_node_creation_with_null_parent() {
        let node = NavNode::new(
            Vector3::new(1.0, 2.0, 3.0),
            NavNodeType::Origin,
            "Origin".to_string(),
            None,
        );
        
        assert!(node.parent_node.is_none());
        assert_eq!(node.g_cost, 0.0);
        assert_eq!(node.h_cost, 0.0);
        assert_eq!(node.f_cost, 0.0);
    }
    
    #[test]
    fn test_nav_node_with_parent() {
        let parent = Arc::new(NavNode::new(
            Vector3::new(0.0, 0.0, 0.0),
            NavNodeType::Intermediate,
            "Parent".to_string(),
            None,
        ));
        
        let mut node = NavNode::new(
            Vector3::new(1.0, 2.0, 3.0),
            NavNodeType::Destination,
            "Child".to_string(),
            None,
        );
        
        node.parent_node = Some(parent.clone());
        node.g_cost = 10.0;
        node.h_cost = 20.0;
        node.calculate_f_cost();
        
        assert!(node.parent_node.is_some());
        assert_eq!(node.parent_node.as_ref().unwrap().name, "Parent");
        assert_eq!(node.f_cost, 30.0);
    }
}